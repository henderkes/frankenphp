package frankenphp

// NTS pre-fork pool: when libphp is built without ZTS, a C constructor
// in frankenphp.c forks the process N times before Go starts (controlled
// by FRANKENPHP_NTS_WORKERS). Each child is an independent FrankenPHP
// process with its own Go runtime, its own Caddy, and its own
// single-threaded libphp. They all bind the listener with SO_REUSEPORT
// (Caddy enables this by default on Linux/FreeBSD), and the kernel
// distributes incoming connections between them.
//
// initNTSPrefork queries the layout chosen by the constructor and, in
// worker 0 (the original parent), spawns a goroutine that forwards
// SIGTERM/SIGINT to the children so the whole pool shuts down together
// when an orchestrator only signals the main PID.

// #include "frankenphp.h"
import "C"
import (
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// signalForwarderOnce ensures the NTS signal-forwarding goroutine is
// started at most once per process, even if Init runs multiple times
// (e.g. Caddy config reloads).
var signalForwarderOnce sync.Once

// ntsWorkerCount returns the total number of NTS pre-fork workers.
// 0 means pre-fork is inactive (ZTS build, Windows, env unset or invalid).
func ntsWorkerCount() int { return int(C.frankenphp_get_nts_worker_count()) }

// ntsWorkerIndex returns this process's index in the pre-fork pool:
// 0 for the original parent, 1..N-1 for forked children, 0 also when
// pre-fork is inactive.
func ntsWorkerIndex() int { return int(C.frankenphp_get_nts_worker_index()) }

// ntsChildPID returns the PID of the i-th forked child (only meaningful
// in the parent), or 0 if i is out of range or pre-fork is inactive.
func ntsChildPID(i int) int { return int(C.frankenphp_get_nts_child_pid(C.int(i))) }

// initNTSPrefork returns (workerCount, workerIndex). workerCount is 0
// when pre-fork is inactive (ZTS build, Windows, env unset, or env was
// invalid); callers should treat that as the existing single-process
// NTS path.
func initNTSPrefork() (workerCount int, workerIndex int) {
	workerCount = ntsWorkerCount()
	if workerCount <= 1 {
		return 0, 0
	}

	workerIndex = ntsWorkerIndex()

	// Only the original parent (worker 0) tracks child PIDs.
	if workerIndex != 0 {
		return workerCount, workerIndex
	}

	pids := make([]int, 0, workerCount-1)
	for i := 0; i < workerCount-1; i++ {
		if pid := ntsChildPID(i); pid > 0 {
			pids = append(pids, pid)
		}
	}

	if len(pids) > 0 {
		signalForwarderOnce.Do(func() {
			go forwardSignalsToNTSChildren(pids)
		})
	}

	return workerCount, workerIndex
}

// forwardSignalsToNTSChildren listens for SIGTERM/SIGINT and forwards
// them to the forked workers. Caddy installs its own signal.Notify
// handlers for these, so the parent's own graceful shutdown still
// runs - signal.Notify is a fan-out, not a consume. SIGINT from a
// foreground process group reaches every child directly already, but
// systemd/k8s by default only signal the main PID, so this fan-out
// covers those cases.
//
// Runs for the lifetime of the parent process (started once via
// signalForwarderOnce). Loops so subsequent signals are also forwarded.
func forwardSignalsToNTSChildren(pids []int) {
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	for sig := range sigs {
		for _, pid := range pids {
			// ESRCH (child already exited) is benign here.
			_ = syscall.Kill(pid, sig.(syscall.Signal))
		}

		if globalLogger.Enabled(globalCtx, slog.LevelDebug) {
			globalLogger.LogAttrs(globalCtx, slog.LevelDebug, "forwarded signal to NTS workers",
				slog.String("signal", sig.String()),
				slog.Int("children", len(pids)))
		}
	}
}
