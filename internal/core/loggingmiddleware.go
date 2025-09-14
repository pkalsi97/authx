package core

import (
	"log"
	"net/http"
	"time"
)

type statusWriter struct {
	http.ResponseWriter
	statusCode int
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		ww := &statusWriter{ResponseWriter: w, statusCode: http.StatusOK}
		next.ServeHTTP(ww, r)

		statusColor := colorForStatus(ww.statusCode)
		methodColor := colorForMethod(r.Method)
		reset := "\033[0m"

		log.Printf("%s%s%s %s%s%s %s%d%s %s",
			methodColor, r.Method, reset,
			"\033[36m", r.URL.Path, reset,
			statusColor, ww.statusCode, reset,
			time.Since(start),
		)
	})
}

func (w *statusWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}

func colorForStatus(code int) string {
	switch {
	case code >= 200 && code < 300:
		return "\033[32m"
	case code >= 300 && code < 400:
		return "\033[36m"
	case code >= 400 && code < 500:
		return "\033[33m"
	default:
		return "\033[31m"
	}
}

func colorForMethod(method string) string {
	switch method {
	case "GET":
		return "\033[34m"
	case "POST":
		return "\033[32m"
	case "PUT":
		return "\033[33m"
	case "DELETE":
		return "\033[31m"
	default:
		return "\033[37m"
	}
}
