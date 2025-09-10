package core

import (
	"net"
	"net/http"
	"strings"

	"github.com/pkalsi97/authx/internal/models"
)

func ExtractRequestMetadata(r *http.Request) *models.AuditMetadata {
	var ip string

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		ip = strings.TrimSpace(parts[0])
	}

	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		ip = xrip
	}

	if ip == "" {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		} else {
			ip = host
		}
	}

	return &models.AuditMetadata{
		IP:        ip,
		UserAgent: r.UserAgent(),
		Method:    r.Method,
		Path:      r.URL.Path,
		Query:     r.URL.RawQuery,
	}
}
