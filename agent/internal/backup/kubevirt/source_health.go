//go:build kubevirt

package kubevirt

import (
	"context"
	"crypto/tls"
	"net/http"
	"time"

	"vnbui/agent/internal/config"
	"vnbui/agent/internal/models"
)

func (e *Executor) sourceHealthURL(r *models.StorageTransactionRequest) (string, error) {
	probes, err := config.ParseSourceHealthProbes(e.cfg.SourceHealthProbesJSON)
	if err != nil {
		return "", fault("admission", "service_probe_configuration_invalid", "refused")
	}
	for _, p := range probes {
		if p.Namespace == r.Plan.Source.Namespace && p.VMName == r.Plan.VMName {
			return p.URL, nil
		}
	}
	return "", nil
}

func inspectServiceHealth(ctx context.Context, g *operationSafety) error {
	u := g.snapshot().ServiceProbeURL
	if u == "" {
		return nil // VM Ready alone is not evidence of application health.
	}
	// Dedicated transport: never forward backend mTLS, agent keys, S3 headers,
	// environment proxy credentials or redirects to the monitored application.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, MaxResponseHeaderBytes: 16 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return fault("source_health", "service_probe_configuration_invalid", "refused")
	}
	resp, err := client.Do(req)
	if err != nil {
		return fault("source_health", "service_health_unavailable", "transient")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		f := fault("source_health", "service_health_refused", "refused")
		f.HTTPStatus = resp.StatusCode
		return f
	}
	return nil
}
