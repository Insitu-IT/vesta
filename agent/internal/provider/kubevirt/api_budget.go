//go:build kubevirt

package kubevirt

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
	"vnbui/agent/internal/metrics"
)

// SetAPIBudget configures startup only. Every typed and dynamic client shares
// this budget, including backup admission, inventory and restore.
func (p *Provider) SetAPIBudget(qps, burst int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.connected {
		p.apiQPS, p.apiBurst = qps, burst
	}
}

func configureAPIBudget(cfg *rest.Config, qps, burst int) error {
	if qps < 1 || qps > 200 || burst < qps || burst > 400 {
		return fmt.Errorf("invalid Kubernetes API request budget")
	}
	cfg.QPS, cfg.Burst = float32(qps), burst
	// Setting QPS alone creates separate buckets per client. Assign one limiter
	// before constructing either client so the agent has a bounded total budget.
	cfg.RateLimiter = &measuredLimiter{RateLimiter: flowcontrol.NewTokenBucketRateLimiter(cfg.QPS, burst)}
	cfg.Wrap(func(next http.RoundTripper) http.RoundTripper { return measuredTransport{next} })
	return nil
}

type measuredLimiter struct{ flowcontrol.RateLimiter }

func (l *measuredLimiter) Wait(ctx context.Context) error {
	started := time.Now()
	err := l.RateLimiter.Wait(ctx)
	metrics.KubeAPIThrottleSeconds.Observe(time.Since(started).Seconds())
	return err
}

type measuredTransport struct{ next http.RoundTripper }

func (t measuredTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// Bound ordinary API requests without imposing a lifetime on watches.
	// Watch callers already own their history/deadline and recovery contract.
	cancel := func() {}
	if watch := r.URL.Query().Get("watch"); watch != "true" && watch != "1" {
		ctx, done := context.WithTimeout(r.Context(), apiTimeout)
		r, cancel = r.Clone(ctx), done
	}
	started := time.Now()
	response, err := t.next.RoundTrip(r)
	seconds := time.Since(started).Seconds()
	metrics.KubeAPIRequestSeconds.Observe(seconds)
	method, resource, status := apiMetricLabels(r, response, err)
	metrics.KubeAPIRequests.WithLabelValues(method, resource, status).Inc()
	metrics.KubeAPIResourceSeconds.WithLabelValues(method, resource).Observe(seconds)
	if err != nil || response == nil || response.Body == nil {
		cancel()
	} else {
		response.Body = &requestBody{ReadCloser: response.Body, cancel: cancel}
	}
	return response, err
}

type requestBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *requestBody) Close() error { defer b.cancel(); return b.ReadCloser.Close() }
