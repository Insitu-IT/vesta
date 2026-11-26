package api

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"vnbui/agent/internal/metrics"
)

// OrchestratorKeyAuth validates the X-Orchestrator-Key header.
func OrchestratorKeyAuth(key string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}

			provided := r.Header.Get("X-Orchestrator-Key")
			if provided == "" {
				metrics.AuthAttemptsTotal.WithLabelValues("api_key", "missing").Inc()
				http.Error(w, `{"detail":"Missing X-Orchestrator-Key header"}`, http.StatusUnauthorized)
				return
			}
			if provided != key {
				metrics.AuthAttemptsTotal.WithLabelValues("api_key", "invalid").Inc()
				http.Error(w, `{"detail":"Invalid orchestrator key"}`, http.StatusForbidden)
				return
			}

			metrics.AuthAttemptsTotal.WithLabelValues("api_key", "success").Inc()
			next.ServeHTTP(w, r)
		})
	}
}

// IPWhitelist restricts access to specific IPs.
func IPWhitelist(allowed []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(allowed) == 0 {
				next.ServeHTTP(w, r)
				return
			}

			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				ip = r.RemoteAddr
			}

			for _, a := range allowed {
				if ip == strings.TrimSpace(a) {
					next.ServeHTTP(w, r)
					return
				}
			}

			http.Error(w, fmt.Sprintf(`{"detail":"IP %s not in whitelist"}`, ip), http.StatusForbidden)
		})
	}
}

// RequestLogger logs requests with timing.
func RequestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap ResponseWriter to capture status code
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)

		duration := time.Since(start)

		// Skip /health and /metrics from verbose logging
		if r.URL.Path != "/health" && r.URL.Path != "/metrics" {
			slog.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"duration_ms", duration.Milliseconds(),
				"remote", r.RemoteAddr,
			)
		}

		// Record metrics
		metrics.HTTPRequestsTotal.WithLabelValues(
			r.Method,
			r.URL.Path,
			strconv.Itoa(sw.status),
		).Inc()
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}
