package frankenphp

// #include "frankenphp.h"
import "C"
import (
	"context"
	"log/slog"
	"math"
	"sync"
	"sync/atomic"
)

// logLevelGateOpen disables the C-side log level gate: every message crosses
// into Go and is filtered there.
const logLevelGateOpen = int32(math.MinInt32)

var (
	// logLevelGate mirrors the C-side frankenphp_min_log_level gate.
	logLevelGate atomic.Int32
	// logLevelGateMu serializes writes to the gate and its C-side copy.
	logLevelGateMu sync.Mutex
	// lastGateLogger is the last per-request logger probed, to avoid
	// re-probing the same logger on every request.
	lastGateLogger atomic.Pointer[slog.Logger]
)

// effectiveMinLogLevel returns the lowest slog level actually emitted by
// logger, assuming (as log/slog documents for handlers) that Enabled is
// monotonic in the level.
func effectiveMinLogLevel(ctx context.Context, logger *slog.Logger) int32 {
	// Custom levels below DEBUG ("trace") may be enabled too: don't gate
	// anything on the C side in that case.
	if logger.Enabled(ctx, slog.LevelDebug) {
		return logLevelGateOpen
	}

	for l := slog.LevelDebug + 1; l <= slog.LevelError; l++ {
		if logger.Enabled(ctx, l) {
			return int32(l)
		}
	}

	// Nothing at or below ERROR is enabled. Messages above ERROR still
	// cross into Go and are filtered exactly there.
	return int32(slog.LevelError) + 1
}

// updateLogLevelGate recomputes the C-side gate from the global logger.
// Must be called whenever globalLogger is (re)installed.
func updateLogLevelGate() {
	logLevelGateMu.Lock()
	defer logLevelGateMu.Unlock()

	lastGateLogger.Store(nil)
	lvl := effectiveMinLogLevel(globalCtx, globalLogger)
	logLevelGate.Store(lvl)
	C.frankenphp_min_log_level = C.int(lvl)
}

// lowerLogLevelGate opens the C-side gate further if a per-request logger is
// more verbose than the loggers seen so far. Between two global
// recomputations the gate only ever becomes more permissive, so messages are
// never lost; exact filtering always happens on the Go side.
func lowerLogLevelGate(logger *slog.Logger) {
	if logger == lastGateLogger.Load() {
		return
	}

	if lvl := effectiveMinLogLevel(globalCtx, logger); lvl < logLevelGate.Load() {
		logLevelGateMu.Lock()
		if lvl < logLevelGate.Load() {
			logLevelGate.Store(lvl)
			C.frankenphp_min_log_level = C.int(lvl)
		}
		logLevelGateMu.Unlock()
	}

	lastGateLogger.Store(logger)
}
