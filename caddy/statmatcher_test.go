package caddy

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/fileserver"
)

// buildStatMatcherTestRoot creates a document root exercising files,
// directories, path info, a directory named like a PHP file, glob
// characters in names and a file outside the root (traversal target).
func buildStatMatcherTestRoot(t *testing.T) string {
	t.Helper()

	base := t.TempDir()
	root := filepath.Join(base, "root")

	for _, dir := range []string{
		root,
		filepath.Join(root, "subdir"),
		filepath.Join(root, "emptydir"),
		filepath.Join(root, "x.php"), // a directory named like a PHP file
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	for _, file := range []string{
		filepath.Join(root, "index.php"),
		filepath.Join(root, "foo.txt"),
		filepath.Join(root, "with space.txt"),
		filepath.Join(root, "star*file.txt"), // glob metacharacter in name
		filepath.Join(root, "subdir", "index.php"),
		filepath.Join(root, "x.php", "index.php"),
		filepath.Join(base, "secret.txt"), // outside the root: traversal target
	} {
		if err := os.WriteFile(file, []byte("test"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return root
}

func newStatMatcherTestRequest(t *testing.T, rawPath string, vars map[string]any) (*http.Request, *caddy.Replacer) {
	t.Helper()

	u, err := url.Parse(rawPath)
	if err != nil {
		t.Fatalf("parsing path %q: %v", rawPath, err)
	}

	req := &http.Request{URL: u}
	if vars != nil {
		req = req.WithContext(context.WithValue(context.Background(), caddyhttp.VarsCtxKey, vars))
	}
	repl := caddyhttp.NewTestReplacer(req)

	return req, repl
}

// TestMatchFileStatEqualsStockMatcher checks, for every try_files shape
// FrankenPHP emits (plus edge shapes), that MatchFileStat returns exactly
// the same match result and the same four {http.matchers.file.*}
// placeholders as the stock fileserver.MatchFile it substitutes.
func TestMatchFileStatEqualsStockMatcher(t *testing.T) {
	root := buildStatMatcherTestRoot(t)

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	shapes := map[string]fileserver.MatchFile{
		// php_server / php-server canonical-dir redirect route
		"redir": {
			Root:     root,
			TryFiles: []string{"{http.request.uri.path}/index.php"},
		},
		// php_server rewrite route (Linux default policy)
		"rewriteFallback": {
			Root:      root,
			TryFiles:  []string{"{http.request.uri.path}", "{http.request.uri.path}/index.php", "index.php"},
			TryPolicy: "first_exist_fallback",
			SplitPath: []string{".php"},
		},
		// php-server command rewrite route (no explicit policy)
		"rewritePlain": {
			Root:      root,
			TryFiles:  []string{"{http.request.uri.path}", "{http.request.uri.path}/index.php", "index.php"},
			SplitPath: []string{".php"},
		},
		// worker 'match' file route
		"worker": {
			Root:     root,
			TryFiles: []string{"{http.request.uri.path}"},
		},
		// fallback policy whose last candidate does not exist
		"missingFallback": {
			Root:      root,
			TryFiles:  []string{"{http.request.uri.path}", "missing.php"},
			TryPolicy: "first_exist_fallback",
		},
		// placeholder root resolving through {http.vars.root}
		"placeholderRoot": {
			TryFiles:  []string{"{http.request.uri.path}", "index.php"},
			TryPolicy: "first_exist_fallback",
			SplitPath: []string{".php"},
		},
	}

	paths := []string{
		"/",
		"/index.php",
		"/index.php/",
		"/index.php/extra/path",
		"/index.PHP/extra/path", // case-insensitive split
		"/foo.txt",
		"/foo.txt/",
		"/subdir",
		"/subdir/",
		"/subdir/index.php",
		"/emptydir",
		"/emptydir/",
		"/x.php",
		"/x.php/",
		"/missing",
		"/missing/",
		"/missing.php",
		"/with%20space.txt",     // URL-encoded space
		"/star%2Afile.txt",      // URL-encoded glob metacharacter
		"/star*file.txt",        // literal glob metacharacter
		"/..%2f..%2fsecret.txt", // URL-encoded traversal attempt
		"/../secret.txt",        // literal traversal attempt
		"/%2e%2e/secret.txt",    // URL-encoded dot segments
		"//index.php",           // duplicate slashes
		"/subdir/../foo.txt",    // in-tree dot segments
	}

	placeholderKeys := []string{
		"http.matchers.file.relative",
		"http.matchers.file.absolute",
		"http.matchers.file.type",
		"http.matchers.file.remainder",
	}

	for shapeName, shape := range shapes {
		stock := shape
		if err := stock.Provision(caddyCtx); err != nil {
			t.Fatalf("%s: provisioning stock matcher: %v", shapeName, err)
		}

		stat := &MatchFileStat{
			Root:      shape.Root,
			TryFiles:  shape.TryFiles,
			TryPolicy: shape.TryPolicy,
			SplitPath: shape.SplitPath,
		}
		if err := stat.Provision(caddyCtx); err != nil {
			t.Fatalf("%s: provisioning stat matcher: %v", shapeName, err)
		}

		var vars map[string]any
		if shapeName == "placeholderRoot" {
			vars = map[string]any{"root": root}
		}

		for _, p := range paths {
			stockReq, stockRepl := newStatMatcherTestRequest(t, p, vars)
			stockMatch, stockErr := stock.MatchWithError(stockReq)

			statReq, statRepl := newStatMatcherTestRequest(t, p, vars)
			statMatch, statErr := stat.MatchWithError(statReq)

			if stockMatch != statMatch {
				t.Errorf("%s %q: match mismatch: stock=%t stat=%t", shapeName, p, stockMatch, statMatch)
				continue
			}
			if (stockErr == nil) != (statErr == nil) {
				t.Errorf("%s %q: error mismatch: stock=%v stat=%v", shapeName, p, stockErr, statErr)
			}

			for _, key := range placeholderKeys {
				stockVal, stockOk := stockRepl.Get(key)
				statVal, statOk := statRepl.Get(key)
				if stockOk != statOk || stockVal != statVal {
					t.Errorf("%s %q: placeholder %s mismatch: stock=(%v,%t) stat=(%v,%t)", shapeName, p, key, stockVal, stockOk, statVal, statOk)
				}
			}
		}
	}
}

// TestMatchFileStatDelegatesOnRequestFS ensures that a request-scoped
// filesystem selection ({http.vars.fs}) takes the stock code path and
// yields the same result as the stock matcher.
func TestMatchFileStatDelegatesOnRequestFS(t *testing.T) {
	root := buildStatMatcherTestRoot(t)

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	shape := fileserver.MatchFile{Root: root, TryFiles: []string{"{http.request.uri.path}"}}

	stock := shape
	if err := stock.Provision(caddyCtx); err != nil {
		t.Fatal(err)
	}
	stat := &MatchFileStat{Root: shape.Root, TryFiles: shape.TryFiles}
	if err := stat.Provision(caddyCtx); err != nil {
		t.Fatal(err)
	}

	// "custom" is not registered, so the stock matcher does not match even
	// though the file exists; the stat matcher must behave identically
	vars := map[string]any{"fs": "custom"}

	stockReq, _ := newStatMatcherTestRequest(t, "/foo.txt", vars)
	stockMatch, _ := stock.MatchWithError(stockReq)

	statReq, _ := newStatMatcherTestRequest(t, "/foo.txt", vars)
	statMatch, _ := stat.MatchWithError(statReq)

	if stockMatch != statMatch {
		t.Errorf("match mismatch with request-scoped fs: stock=%t stat=%t", stockMatch, statMatch)
	}
	if statMatch {
		t.Error("expected no match with an unregistered request-scoped filesystem")
	}
}

// TestMatchFileStatProvisionRejectsUnsupportedShapes ensures the module
// refuses configurations it cannot replicate.
func TestMatchFileStatProvisionRejectsUnsupportedShapes(t *testing.T) {
	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	for name, m := range map[string]*MatchFileStat{
		"glob":              {TryFiles: []string{"*.php"}},
		"otherPlaceholder":  {TryFiles: []string{"{http.request.host}.php"}},
		"statusFallback":    {TryFiles: []string{"{http.request.uri.path}", "=404"}},
		"unsupportedPolicy": {TryFiles: []string{"{http.request.uri.path}"}, TryPolicy: "smallest_size"},
		"emptyTryFiles":     {},
	} {
		if err := m.Provision(caddyCtx); err == nil {
			t.Errorf("%s: expected provision error, got nil", name)
		}
	}
}

// TestFileMatcherModuleSubstitutesOnlyDefaultShapes checks the
// config-generation helper: the stat matcher is substituted for the
// try_files shapes php_server/php-server emit by default, and the stock
// file matcher is kept for anything it cannot replicate (and when the
// escape hatch is used).
func TestFileMatcherModuleSubstitutesOnlyDefaultShapes(t *testing.T) {
	substituted := map[string]fileserver.MatchFile{
		"redirRoute": {
			Root:     "/srv/app/public",
			TryFiles: []string{"{http.request.uri.path}/index.php"},
		},
		"rewriteRouteFallback": {
			Root:      "/srv/app/public",
			TryFiles:  []string{"{http.request.uri.path}", "{http.request.uri.path}/index.php", "index.php"},
			TryPolicy: "first_exist_fallback",
			SplitPath: []string{".php"},
		},
		"rewriteRouteFirstExist": {
			Root:      "/srv/app/public",
			TryFiles:  []string{"{http.request.uri.path}", "{http.request.uri.path}/index.php", "index.php"},
			TryPolicy: "first_exist",
			SplitPath: []string{".php"},
		},
		"workerFileRoute": {
			Root:     "/srv/app/public",
			TryFiles: []string{"{http.request.uri.path}"},
		},
		"customIndex": {
			Root:     "/srv/app/public",
			TryFiles: []string{"{http.request.uri.path}/app.php"},
		},
		"placeholderRoot": {
			Root:     "{http.vars.root}",
			TryFiles: []string{"{http.request.uri.path}"},
		},
	}
	for name, m := range substituted {
		modName, val := fileMatcherModule(m, false)
		if modName != "frankenphp_file_stat" {
			t.Errorf("%s: expected substitution, got module %q", name, modName)
			continue
		}
		stat, ok := val.(MatchFileStat)
		if !ok {
			t.Errorf("%s: expected a MatchFileStat value, got %T", name, val)
			continue
		}
		if stat.Root != m.Root || stat.TryPolicy != m.TryPolicy ||
			len(stat.TryFiles) != len(m.TryFiles) || len(stat.SplitPath) != len(m.SplitPath) {
			t.Errorf("%s: substituted matcher does not mirror the stock config: %+v vs %+v", name, stat, m)
		}
	}

	kept := map[string]fileserver.MatchFile{
		"globTryFiles":     {TryFiles: []string{"{http.request.uri.path}", "/assets/*.php"}},
		"otherPlaceholder": {TryFiles: []string{"{http.request.uri.path}", "{http.request.host}/index.php"}},
		"statusFallback":   {TryFiles: []string{"{http.request.uri.path}", "=404"}},
		"sizePolicy":       {TryFiles: []string{"{http.request.uri.path}"}, TryPolicy: "smallest_size"},
		"customFilesystem": {TryFiles: []string{"{http.request.uri.path}"}, FileSystem: "s3"},
		"emptyTryFiles":    {},
		"globInRoot":       {Root: "/srv/app*/public", TryFiles: []string{"{http.request.uri.path}"}},
	}
	for name, m := range kept {
		if modName, _ := fileMatcherModule(m, false); modName != "file" {
			t.Errorf("%s: expected stock file matcher, got module %q", name, modName)
		}
	}

	// the escape hatch always keeps the stock matcher
	if modName, _ := fileMatcherModule(substituted["redirRoute"], true); modName != "file" {
		t.Errorf("disable_stat_matcher: expected stock file matcher, got module %q", modName)
	}
}
