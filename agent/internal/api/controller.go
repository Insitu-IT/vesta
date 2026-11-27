package api

import (
	"crypto/tls"
	"net/http"
	"time"

	"vnbui/agent/internal/config"
)

func controllerAuth(cfg *config.Config, serverTLS *tls.Config, role config.ControllerRole) func(http.Handler) http.Handler {
	readyTLS := serverTLS != nil && (serverTLS.ClientAuth == tls.RequireAndVerifyClientCert ||
		serverTLS.ClientAuth == tls.VerifyClientCertIfGiven)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			refuse := func(status int, detail string) {
				writeJSON(w, status, map[string]string{"detail": detail})
			}
			if !readyTLS || !cfg.EnableAPIKeyValidation || cfg.OrchestratorAPIKey == "" {
				refuse(http.StatusLocked, "configure verified agent mTLS and the orchestrator key for controller operations")
				return
			}
			if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
				refuse(http.StatusForbidden, "controller operations require a verified HTTPS client certificate")
				return
			}
			supplied := r.Header.Values("X-Vesta-Agent-ID")
			if cfg.AgentID == "" || len(supplied) != 1 || supplied[0] != cfg.AgentID {
				refuse(http.StatusForbidden, "request must name this enrolled agent in X-Vesta-Agent-ID; upgrade the controller together with the agent")
				return
			}
			leaf := r.TLS.VerifiedChains[0][0]
			now := time.Now()
			if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
				refuse(http.StatusForbidden, "controller certificate has expired or is not yet valid")
				return
			}
			ready, matches := cfg.ControllerPeer(role, leaf.Raw)
			if !ready {
				refuse(http.StatusServiceUnavailable, "waiting for a verified controller heartbeat; check enrollment and controller version")
				return
			}
			if !matches {
				refuse(http.StatusForbidden, "request requires this installation's current controller certificate")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
