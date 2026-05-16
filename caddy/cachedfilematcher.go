package caddy

import (
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/fileserver"
)

func init() {
	caddy.RegisterModule(MatchFileCached{})
}

// matchFileCacheEntry holds a cached MatchWithError result.
// match==true means the inner MatchFile matched; placeholders is the
// snapshot Caddy attached to the request context so we can re-apply
// them on a cache hit (try_files needs {http.matchers.file.relative}
// etc. populated for the downstream rewrite).
type matchFileCacheEntry struct {
	match        bool
	err          error
	expiresAt    int64 // unix nano
	placeholders map[string]string
}

// MatchFileCached wraps fileserver.MatchFile with a short-lived
// per-URL-path stat cache. It speeds up the worker hot path where
// try_files keeps stat'ing the same in-tree PHP files at thousands
// of requests per second; on the cache hit path it skips the stat
// syscall entirely and re-applies the placeholders the original
// match would have produced.
//
// Cache TTL is short (default 2s) so file edits during development
// are still picked up reasonably quickly. The watcher subsystem
// invalidates the cache when it sees a file change.
type MatchFileCached struct {
	fileserver.MatchFile

	// CacheTTLMilliseconds is the cache entry lifetime in
	// milliseconds. 0 means default (2000ms). Negative disables
	// caching entirely (falls through to the inner matcher).
	CacheTTLMilliseconds int `json:"cache_ttl_ms,omitempty"`

	cache    sync.Map // map[string]*matchFileCacheEntry
	ttlNanos int64
}

// CaddyModule returns the Caddy module information.
func (MatchFileCached) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.frankenphp_file",
		New: func() caddy.Module { return new(MatchFileCached) },
	}
}

// UnmarshalCaddyfile delegates to the embedded matcher; this matcher
// is meant to be configured via JSON from parsePhpServer, not directly
// from Caddyfile, but supporting the same syntax keeps the module
// usable as a drop-in replacement if anyone ever wires it that way.
func (m *MatchFileCached) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return m.MatchFile.UnmarshalCaddyfile(d)
}

// Provision sets up the inner matcher and the cache TTL.
func (m *MatchFileCached) Provision(ctx caddy.Context) error {
	if err := m.MatchFile.Provision(ctx); err != nil {
		return err
	}
	ttlMs := m.CacheTTLMilliseconds
	if ttlMs == 0 {
		ttlMs = 2000
	}
	m.ttlNanos = int64(ttlMs) * int64(time.Millisecond)
	return nil
}

// MatchWithError checks the cache before delegating to MatchFile. On
// a cache hit it re-applies the captured placeholders so subsequent
// handlers (typically a rewrite) see the same {http.matchers.file.*}
// values they would have on a cold match.
func (m *MatchFileCached) MatchWithError(r *http.Request) (bool, error) {
	if m.ttlNanos < 0 {
		return m.MatchFile.MatchWithError(r)
	}

	key := r.URL.Path
	now := time.Now().UnixNano()

	if v, ok := m.cache.Load(key); ok {
		entry := v.(*matchFileCacheEntry)
		if atomic.LoadInt64(&entry.expiresAt) > now {
			if entry.match && entry.placeholders != nil {
				repl := matchFileReplacer(r)
				for k, val := range entry.placeholders {
					repl.Set(k, val)
				}
			}
			return entry.match, entry.err
		}
	}

	repl := matchFileReplacer(r)
	preKeys := captureMatchFilePlaceholders(repl)
	match, err := m.MatchFile.MatchWithError(r)
	placeholders := diffMatchFilePlaceholders(repl, preKeys)

	entry := &matchFileCacheEntry{
		match:        match,
		err:          err,
		expiresAt:    now + m.ttlNanos,
		placeholders: placeholders,
	}
	m.cache.Store(key, entry)

	return match, err
}

// Match forwards to MatchWithError for the deprecated single-value
// matcher API; without this the embedded MatchFile.Match would be
// promoted and run against the inner matcher directly, bypassing the
// cache.
func (m *MatchFileCached) Match(r *http.Request) bool {
	match, _ := m.MatchWithError(r)
	return match
}

// matchFilePlaceholderKeys lists the placeholders fileserver.MatchFile
// populates on a successful match; we cache only these to avoid hanging
// onto every replacer key in the request.
var matchFilePlaceholderKeys = [...]string{
	"http.matchers.file.relative",
	"http.matchers.file.absolute",
	"http.matchers.file.type",
	"http.matchers.file.remainder",
}

func matchFileReplacer(r *http.Request) *caddy.Replacer {
	if v := r.Context().Value(caddy.ReplacerCtxKey); v != nil {
		if repl, ok := v.(*caddy.Replacer); ok {
			return repl
		}
	}
	return caddy.NewReplacer()
}

func captureMatchFilePlaceholders(repl *caddy.Replacer) map[string]string {
	pre := make(map[string]string, len(matchFilePlaceholderKeys))
	for _, k := range matchFilePlaceholderKeys {
		if v, ok := repl.GetString(k); ok {
			pre[k] = v
		}
	}
	return pre
}

func diffMatchFilePlaceholders(repl *caddy.Replacer, pre map[string]string) map[string]string {
	var out map[string]string
	for _, k := range matchFilePlaceholderKeys {
		v, ok := repl.GetString(k)
		if !ok {
			continue
		}
		if old, hadOld := pre[k]; hadOld && old == v {
			continue
		}
		if out == nil {
			out = make(map[string]string, len(matchFilePlaceholderKeys))
		}
		out[k] = v
	}
	return out
}

// Interface guards
var (
	_ caddy.Provisioner          = (*MatchFileCached)(nil)
	_ caddy.Module               = MatchFileCached{}
	_ caddyhttp.RequestMatcher   = (*MatchFileCached)(nil)
	_ caddyfile.Unmarshaler      = (*MatchFileCached)(nil)
)
