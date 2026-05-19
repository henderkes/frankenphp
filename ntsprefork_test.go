package frankenphp

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNTSPreforkInactive verifies the getters return zero in the
// default configuration (no FRANKENPHP_NTS_WORKERS env). Under ZTS the
// pre-fork is also disabled and the getters always return 0.
func TestNTSPreforkInactive(t *testing.T) {
	// This test must run without FRANKENPHP_NTS_WORKERS set, otherwise
	// the C constructor would have forked the test binary itself.
	if os.Getenv("FRANKENPHP_NTS_WORKERS") != "" {
		t.Skip("FRANKENPHP_NTS_WORKERS is set; constructor already forked the test binary")
	}

	assert.Equal(t, 0, ntsWorkerCount())
	assert.Equal(t, 0, ntsWorkerIndex())
	assert.Equal(t, 0, ntsChildPID(0))
}

// TestNTSPreforkSubprocess re-executes the test binary with
// FRANKENPHP_NTS_WORKERS set so the C constructor forks; the child
// processes print their worker layout and we check the output.
//
// Skipped on ZTS builds (the constructor short-circuits) and on
// Windows (no fork(2)). Re-uses TestHelperPreforkProcess as the child
// entry point - a standard Go pattern from os/exec's own tests.
func TestNTSPreforkSubprocess(t *testing.T) {
	if Config().ZTS {
		t.Skip("pre-fork only applies to NTS builds")
	}
	if runtime.GOOS == "windows" {
		t.Skip("fork(2) not supported on Windows")
	}
	if os.Getenv("FRANKENPHP_NTS_WORKERS") != "" {
		t.Skip("test binary was itself pre-forked; can't nest")
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperPreforkProcess")
	cmd.Env = append(os.Environ(),
		"GO_WANT_HELPER_PROCESS=1",
		"FRANKENPHP_NTS_WORKERS=3",
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "child output:\n%s", out)

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")

	// Each of the 3 workers should emit one WORKER= line.
	indices := map[int]bool{}
	for _, l := range lines {
		if !strings.HasPrefix(l, "WORKER=") {
			continue
		}
		fields := strings.Split(strings.TrimPrefix(l, "WORKER="), ",")
		require.Len(t, fields, 2, "unexpected output: %q (full output:\n%s)", l, out)

		idx, err := strconv.Atoi(fields[0])
		require.NoError(t, err)
		cnt, err := strconv.Atoi(fields[1])
		require.NoError(t, err)

		assert.Equal(t, 3, cnt, "worker_count")
		indices[idx] = true
	}

	assert.Equal(t, map[int]bool{0: true, 1: true, 2: true}, indices,
		"expected one line per worker index 0..2, got:\n%s", out)
}

// TestHelperPreforkProcess is the child entry point for the subprocess
// test above. It is also exposed as a normal test, so it must be a
// no-op unless GO_WANT_HELPER_PROCESS is set.
func TestHelperPreforkProcess(_ *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}

	cnt := ntsWorkerCount()
	idx := ntsWorkerIndex()
	// Tagged line so the parent can pick it out of the test binary's
	// chatty stdout. Write through stdout directly so it isn't gated
	// by the verbose flag like t.Logf would be.
	fmt.Printf("WORKER=%d,%d\n", idx, cnt)
	_ = os.Stdout.Sync()

	// Worker 0 (the original process the parent test waited on)
	// must reap its forked children before exiting, otherwise their
	// output is racy: cmd.Wait() returns when worker 0 exits, and any
	// later writes from workers 1..N may be dropped.
	if idx == 0 {
		for i := 0; i < cnt-1; i++ {
			if pid := ntsChildPID(i); pid > 0 {
				var ws syscall.WaitStatus
				_, _ = syscall.Wait4(pid, &ws, 0, nil)
			}
		}
	}

	// Bypass the test framework's defer chain so each forked child
	// exits cleanly without waiting for siblings.
	os.Exit(0)
}
