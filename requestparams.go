package frankenphp

import (
	"log/slog"
	"net/http"
	"os"
)

// RequestParams contains the parameters needed to serve a request with
// ServeHTTPWithParams. The handler-independent fields can be computed once
// (e.g. at provisioning time) and reused for every request, avoiding the
// per-request closure and context allocations of NewRequestWithContext.
type RequestParams struct {
	mercureContext

	// DocumentRoot is the root directory of the PHP application.
	// If empty, EmbeddedAppPath or the current working directory is used.
	DocumentRoot string
	// ResolveDocumentRoot indicates that DocumentRoot is not known to be
	// absolute yet and must be resolved (result is cached).
	ResolveDocumentRoot bool
	// SplitPath, normalized as by WithRequestSplitPath (lower-case ASCII).
	SplitPath []string
	// Env is the prepared environment (see PrepareEnv).
	Env PreparedEnv
	// Logger is the logger associated with the request (defaults to the global logger).
	Logger *slog.Logger
	// WorkerName is the name of the worker that should handle the request, if any.
	WorkerName string
	// OriginalRequestURI is the URI of the request before any rewrite (optional).
	OriginalRequestURI string
}

// ServeHTTPWithParams executes a PHP script according to the given request
// and pre-computed parameters.
//
// It is a faster equivalent of NewRequestWithContext followed by ServeHTTP:
// no request clone and no context values are allocated.
//
// The same security considerations as for NewRequestWithContext apply:
// headers containing underscores must be dropped by the caller.
func ServeHTTPWithParams(responseWriter http.ResponseWriter, request *http.Request, params RequestParams) error {
	h := responseWriter.Header()
	if h["Server"] == nil {
		h["Server"] = serverHeader
	}

	if !isRunning {
		return ErrNotRunning
	}

	fc := newFrankenPHPContext()
	fc.mercureContext = params.mercureContext
	fc.request = request
	fc.splitPath = params.SplitPath
	fc.env = params.Env
	fc.originalRequestURI = params.OriginalRequestURI

	if params.Logger == nil {
		fc.logger = globalLogger
	} else {
		fc.logger = params.Logger
	}

	if params.WorkerName != "" {
		fc.worker = workersByName[params.WorkerName]
	}

	documentRoot := params.DocumentRoot
	if documentRoot == "" {
		if EmbeddedAppPath != "" {
			documentRoot = EmbeddedAppPath
		} else {
			var err error
			if documentRoot, err = os.Getwd(); err != nil {
				return err
			}
		}
	} else if params.ResolveDocumentRoot {
		var err error
		if documentRoot, err = absDocumentRoot(documentRoot); err != nil {
			return err
		}
	}
	fc.documentRoot = documentRoot

	splitCgiPath(fc)

	fc.requestURI = request.URL.RequestURI()
	fc.responseWriter = responseWriter

	if err := fc.validate(); err != nil {
		return err
	}

	ch := contextHolder{request.Context(), fc}

	// Detect if a worker is available to handle this request
	if fc.worker != nil {
		return fc.worker.handleRequest(ch)
	}

	// If no worker was available, send the request to non-worker threads
	return handleRequestWithRegularPHPThreads(ch)
}
