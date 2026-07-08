package caddy

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/fileserver"
)

func init() {
	caddy.RegisterModule(MatchFileStat{})
}

const (
	// uriPathPlaceholder is the only placeholder the stat matcher resolves
	// natively; it maps to r.URL.Path in Caddy's HTTP replacer.
	uriPathPlaceholder = "{http.request.uri.path}"

	// globMetaChars are the metacharacters (plus the escape character)
	// recognized by path.Match. Values containing any of these take the
	// stock fileserver.MatchFile code path, which glob-escapes and expands
	// them.
	globMetaChars = `*?[\`

	// statSeparator mirrors the fileserver package's unexported separator
	// constant, used for the trailing-separator file/directory convention.
	statSeparator = string(filepath.Separator)

	statTryPolicyFirstExist         = "first_exist"
	statTryPolicyFirstExistFallback = "first_exist_fallback"
)

// MatchFileStat is a drop-in, faster replacement for the standard `file`
// matcher (fileserver.MatchFile) that FrankenPHP substitutes at
// config-generation time for the try_files shapes it emits itself.
//
// Rationale: Caddy wraps every filesystem (including the default OS
// filesystem) in an internal wrapper that only embeds the fs.FS interface,
// hiding the fs.StatFS/fs.GlobFS implementations of its OsFS. As a result,
// each fs.Stat performed by fileserver.MatchFile degrades to
// Open+Stat+Close (3+ syscalls and an os.File allocation), and fs.Glob
// degrades to the pure-Go fallback which performs that same expensive Stat
// even for glob-free patterns. The default php_server subroute evaluates a
// file matcher twice per request (canonical-dir redirect + try_files
// rewrite), so this adds up to ~6-9 syscalls per request.
//
// MatchFileStat performs a single os.Stat (one statx syscall) per
// candidate instead, while replicating fileserver.MatchFile's observable
// behavior exactly: SanitizedPathJoin traversal protection, split_path
// handling, strict trailing-slash file/directory conventions,
// first_exist/first_exist_fallback try policies, and the four
// {http.matchers.file.*} placeholders.
//
// It only supports the shapes vetted by statMatcherSubstitutable (no glob
// metacharacters, no placeholders other than {http.request.uri.path}, no
// "=status" fallbacks, no custom filesystem, no size/mtime try policies).
// At request time it transparently delegates to a provisioned stock
// fileserver.MatchFile whenever native evaluation could diverge: URL paths
// or resolved roots containing glob metacharacters, a request-scoped
// filesystem selection ({http.vars.fs}), or a replaced default filesystem.
type MatchFileStat struct {
	// The root directory. Accepts placeholders; defaults to
	// {http.vars.root} like the standard file matcher.
	Root string `json:"root,omitempty"`

	// The list of files to try. Only {http.request.uri.path} placeholders
	// are allowed, and no glob metacharacters.
	TryFiles []string `json:"try_files,omitempty"`

	// Either empty, "first_exist" or "first_exist_fallback".
	TryPolicy string `json:"try_policy,omitempty"`

	// A list of delimiters to split the path in two ("path info").
	SplitPath []string `json:"split_path,omitempty"`

	// fallback is a provisioned stock matcher with the exact same
	// configuration, used whenever native evaluation could diverge.
	fallback *fileserver.MatchFile

	fsmap caddy.FileSystems
	// approvedFS caches a default filesystem instance that was verified
	// (via isStockOsFS) to be Caddy's stock OS filesystem. It is a pointer
	// so the struct stays copyable (it is marshaled by value at
	// config-generation time).
	approvedFS *atomic.Pointer[fs.FS]

	root               string
	rootHasPlaceholder bool
	cleanedRoot        string
}

// CaddyModule returns the Caddy module information.
func (MatchFileStat) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.matchers.frankenphp_file_stat",
		New: func() caddy.Module { return new(MatchFileStat) },
	}
}

// Provision sets up the matcher and its stock fallback.
func (m *MatchFileStat) Provision(ctx caddy.Context) error {
	stock := &fileserver.MatchFile{
		Root:      m.Root,
		TryFiles:  m.TryFiles,
		TryPolicy: m.TryPolicy,
		SplitPath: m.SplitPath,
	}

	if !statMatcherSubstitutable(*stock) {
		return fmt.Errorf("frankenphp_file_stat does not support this configuration (root=%q try_files=%v try_policy=%q), use the standard file matcher instead", m.Root, m.TryFiles, m.TryPolicy)
	}

	if err := stock.Provision(ctx); err != nil {
		return err
	}
	m.fallback = stock
	m.fsmap = ctx.FileSystems()
	m.approvedFS = new(atomic.Pointer[fs.FS])

	m.root = m.Root
	if m.root == "" {
		m.root = "{http.vars.root}"
	}
	m.rootHasPlaceholder = strings.Contains(m.root, "{")
	if !m.rootHasPlaceholder {
		m.cleanedRoot = filepath.Clean(m.root)
	}

	return nil
}

// Match returns true if r matches m, mirroring fileserver.MatchFile.Match.
func (m *MatchFileStat) Match(r *http.Request) bool {
	match, err := m.MatchWithError(r)
	if err != nil {
		//nolint:staticcheck
		caddyhttp.SetVar(r.Context(), caddyhttp.MatcherErrorVarKey, err)
	}

	return match
}

// MatchWithError returns true if r matches m. On a match it sets the same
// four placeholders as the standard file matcher:
// {http.matchers.file.relative}, {http.matchers.file.absolute},
// {http.matchers.file.type} and {http.matchers.file.remainder}.
func (m *MatchFileStat) MatchWithError(r *http.Request) (bool, error) {
	repl := r.Context().Value(caddy.ReplacerCtxKey).(*caddy.Replacer)

	// a request-scoped filesystem (fs directive) or a replaced default
	// filesystem must go through the stock matcher, which resolves them
	if fsName, ok := repl.GetString("http.vars.fs"); ok && fsName != "" {
		return m.fallback.MatchWithError(r)
	}
	if !m.defaultFSIsOS() {
		return m.fallback.MatchWithError(r)
	}

	// paths containing glob metacharacters are glob-escaped and expanded
	// by the stock matcher; delegate so the semantics stay identical
	urlPath := r.URL.Path
	if strings.ContainsAny(urlPath, globMetaChars) {
		return m.fallback.MatchWithError(r)
	}

	root := m.cleanedRoot
	if m.rootHasPlaceholder {
		root = filepath.Clean(repl.ReplaceAll(m.root, "."))
		if strings.ContainsAny(root, globMetaChars) {
			return m.fallback.MatchWithError(r)
		}
	}

	maxI := -1
	if m.TryPolicy == statTryPolicyFirstExistFallback {
		maxI = len(m.TryFiles) - 1
	}

	for i, pattern := range m.TryFiles {
		expanded := pattern
		if strings.Contains(pattern, uriPathPlaceholder) {
			expanded = strings.ReplaceAll(pattern, uriPathPlaceholder, urlPath)
		}

		// clean the path and split, if configured; restore the trailing
		// slash if the raw pattern had one (same as the stock matcher)
		beforeSplit, remainder := m.firstSplit(path.Clean(expanded))
		if strings.HasSuffix(pattern, "/") {
			beforeSplit += "/"
		}

		// the traversal-safety layer, identical to the stock matcher
		fullpath := caddyhttp.SanitizedPathJoin(root, beforeSplit)

		if i == maxI {
			// first_exist_fallback: the last candidate matches without the
			// strict file/directory check; except on Windows (where the
			// stock matcher skips globbing entirely), glob expansion still
			// requires the path to exist
			if runtime.GOOS != "windows" {
				if _, err := os.Stat(fullpath); err != nil {
					continue
				}
			}
			setStatMatcherPlaceholders(repl, fullpath, root, remainder, false)

			return true, nil
		}

		info, err := os.Stat(fullpath)
		if err != nil {
			// treat any error as "does not exist", like the stock matcher
			continue
		}

		// replicate strictFileExists: a path ending in the separator must
		// be a directory, otherwise it must NOT be a directory
		if strings.HasSuffix(fullpath, statSeparator) {
			if !info.IsDir() {
				continue
			}
		} else if info.IsDir() {
			continue
		}

		setStatMatcherPlaceholders(repl, fullpath, root, remainder, info.IsDir())

		return true, nil
	}

	return false, nil
}

// defaultFSIsOS reports whether the default filesystem is Caddy's stock OS
// filesystem, so plain os.Stat calls observe the same files. The result is
// cached per filesystem instance; on the hot path this is one map load and
// two pointer comparisons.
func (m *MatchFileStat) defaultFSIsOS() bool {
	fsys, ok := m.fsmap.Get("")
	if !ok {
		return false
	}
	if approved := m.approvedFS.Load(); approved != nil && *approved == fsys {
		return true
	}
	if !isStockOsFS(fsys) {
		return false
	}
	m.approvedFS.Store(&fsys)

	return true
}

// isStockOsFS reports whether fsys is Caddy's default filesystem, i.e. the
// internal wrapperFs around the internal OsFS. The wrapper hides the
// fs.StatFS/fs.GlobFS implementations, so this has to be checked
// structurally.
func isStockOsFS(fsys fs.FS) bool {
	v := reflect.ValueOf(fsys)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return false
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return false
	}
	inner := v.FieldByName("FS")
	if !inner.IsValid() || inner.Kind() != reflect.Interface || inner.IsNil() {
		return false
	}
	t := inner.Elem().Type()

	return t.Name() == "OsFS" && t.PkgPath() == "github.com/caddyserver/caddy/v2/internal/filesystems"
}

// setStatMatcherPlaceholders sets the same placeholders as the stock
// matcher's setPlaceholders.
func setStatMatcherPlaceholders(repl *caddy.Replacer, fullpath, root, remainder string, isDir bool) {
	repl.Set("http.matchers.file.relative", filepath.ToSlash(strings.TrimPrefix(fullpath, root)))
	repl.Set("http.matchers.file.absolute", filepath.ToSlash(fullpath))
	repl.Set("http.matchers.file.remainder", filepath.ToSlash(remainder))

	fileType := "file"
	if isDir {
		fileType = "directory"
	}
	repl.Set("http.matchers.file.type", fileType)
}

// firstSplit is a verbatim copy of fileserver.MatchFile.firstSplit: it
// returns the first result where the path can be split in two by a value
// in m.SplitPath.
func (m *MatchFileStat) firstSplit(path string) (splitPart, remainder string) {
	for _, split := range m.SplitPath {
		if idx := statIndexFold(path, split); idx > -1 {
			pos := idx + len(split)
			// skip the split if it's not the final part of the filename
			if pos != len(path) && !strings.HasPrefix(path[pos:], "/") {
				continue
			}

			return path[:pos], path[pos:]
		}
	}

	return path, ""
}

// statIndexFold is a verbatim copy of the fileserver package's indexFold:
// a case-insensitive substring search (including its quirk of not matching
// a needle that is exactly the suffix of the haystack, which is harmless
// for splitting since such a split has an empty remainder).
func statIndexFold(haystack, needle string) int {
	nlen := len(needle)
	for i := 0; i+nlen < len(haystack); i++ {
		if strings.EqualFold(haystack[i:i+nlen], needle) {
			return i
		}
	}

	return -1
}

// statMatcherSubstitutable reports whether a stock file matcher with the
// given configuration can be replaced by MatchFileStat with identical
// semantics. The default try_files shapes emitted by php_server and the
// php-server command always pass; user overrides using globs, "=status"
// fallbacks, placeholders other than {http.request.uri.path}, custom
// filesystems or size/mtime try policies keep the stock matcher.
func statMatcherSubstitutable(m fileserver.MatchFile) bool {
	if m.FileSystem != "" {
		return false
	}

	switch m.TryPolicy {
	case "", statTryPolicyFirstExist, statTryPolicyFirstExistFallback:
	default:
		return false
	}

	if len(m.TryFiles) == 0 {
		return false
	}
	for _, pattern := range m.TryFiles {
		if strings.HasPrefix(pattern, "=") {
			return false
		}
		rest := strings.ReplaceAll(pattern, uriPathPlaceholder, "")
		if strings.ContainsAny(rest, globMetaChars) || strings.ContainsAny(rest, "{}") {
			return false
		}
	}

	// a literal root must not contain glob metacharacters (the stock
	// matcher would expand them); placeholder roots are re-checked per
	// request after resolution
	if !strings.Contains(m.Root, "{") && strings.ContainsAny(m.Root, globMetaChars) {
		return false
	}

	return true
}

// fileMatcherModule returns the matcher module name and value to embed in
// a matcher set for the given file matcher configuration: the native
// stat-based matcher when a semantics-preserving substitution is possible,
// the stock "file" matcher otherwise (or when disabled).
func fileMatcherModule(m fileserver.MatchFile, disableStatMatcher bool) (string, any) {
	if !disableStatMatcher && statMatcherSubstitutable(m) {
		return "frankenphp_file_stat", MatchFileStat{
			Root:      m.Root,
			TryFiles:  m.TryFiles,
			TryPolicy: m.TryPolicy,
			SplitPath: m.SplitPath,
		}
	}

	return "file", m
}

// Interface guards
var (
	_ caddy.Provisioner                 = (*MatchFileStat)(nil)
	_ caddyhttp.RequestMatcher          = (*MatchFileStat)(nil)
	_ caddyhttp.RequestMatcherWithError = (*MatchFileStat)(nil)
)
