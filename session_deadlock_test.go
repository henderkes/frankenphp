package frankenphp_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dunglas/frankenphp"
)

// Regression for php/frankenphp#2368. Fires three requests staggered by 1s,
// sharing one PHPSESSID, against a 3-thread non-worker pool. R1 holds the
// session flock while running system('sleep 4'). R2's max_execution_time
// timer fires while R2 is stuck in flock; when R1 releases and R2 acquires
// the lock, R2 bails immediately. The leaked FD must not block R3.
func TestSessionDeadlockOnTimeout(t *testing.T) {
	if !frankenphp.Config().ZTS {
		t.Skip("non-ZTS build")
	}
	if !frankenphp.Config().ZendMaxExecutionTimers {
		t.Skip("Zend Max Execution Timers not enabled")
	}

	const concurrency = 3
	const sharedSessionID = "testsession2368xxxxxxxx"
	const startStagger = 1 * time.Second
	const overallBudget = 20 * time.Second

	// StrictSessionHandler discards a session id that doesn't already have a
	// file on disk and generates a fresh one - which would route every request
	// to a different file and skip the lock entirely. Pre-create the file so
	// strict-mode validation accepts the shared id.
	sessionFile := filepath.Join(os.TempDir(), "sess_"+sharedSessionID)
	// Valid PHP session payload (key|serialized) so AbstractSessionHandler::validateId
	// reads non-empty data and accepts the shared id under use_strict_mode=1.
	if err := os.WriteFile(sessionFile, []byte("_token|s:5:\"hello\";"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(sessionFile) })

	runTest(t, func(handler func(http.ResponseWriter, *http.Request), _ *httptest.Server, _ int) {
		var wg sync.WaitGroup
		done := make(chan struct{})
		started := time.Now()

		for i := 0; i < concurrency; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				time.Sleep(time.Duration(idx) * startStagger)
				req := httptest.NewRequest(http.MethodGet, "http://example.com/session-deadlock.php", nil)
				req.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: sharedSessionID})
				body, resp := testRequest(req, handler, t)
				t.Logf("req %d fired at +%s returned at +%s status=%d body=%q",
					idx, time.Duration(idx)*startStagger,
					time.Since(started).Round(time.Millisecond),
					resp.StatusCode, body)
			}(i)
		}

		go func() { wg.Wait(); close(done) }()

		select {
		case <-done:
			t.Logf("all %d requests completed in %s", concurrency, time.Since(started).Round(time.Millisecond))
		case <-time.After(overallBudget):
			t.Fatalf("session flock leaked: not all requests returned within %s (#2368)", overallBudget)
		}
	}, &testOptions{
		nbParallelRequests: 1,
		phpIni: map[string]string{
			"max_execution_time":       "1",
			"session.use_strict_mode":  "0",
			"session.save_path":        "/tmp",
		},
		initOpts: []frankenphp.Option{
			frankenphp.WithNumThreads(concurrency),
		},
	})
}
