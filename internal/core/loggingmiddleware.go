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
		log.Printf("%s %s %d %s",
			r.Method,
			r.URL.Path,
			ww.statusCode,
			time.Since(start),
		)
	})
}

func (w *statusWriter) WriteHeader(code int) {
	w.statusCode = code
	w.ResponseWriter.WriteHeader(code)
}
