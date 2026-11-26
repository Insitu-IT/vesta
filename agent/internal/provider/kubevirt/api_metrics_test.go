//go:build kubevirt

package kubevirt

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"vnbui/agent/internal/metrics"
)

func TestAPIMetricsLabelsStayBounded(t *testing.T) {
	for _, c := range []struct {
		method, path     string
		code             int
		resource, status string
	}{
		{"GET", "/apis/kubevirt.io/v1/namespaces/private-ns/virtualmachineinstances/private-vm", 200, "virtualmachineinstances", "200"},
		{"GET", "/api/v1/namespaces/private-ns/secrets/private-token?token=private", 429, "secrets", "429"},
		{"GET", "/apis/discovery.k8s.io/v1/namespaces/ns/endpointslices", 503, "endpointslices", "503"},
		{"GET", "/api/v1/namespaces/private-name", 404, "namespaces", "404"},
		{"GET", "/apis/private-group/v1/namespaces/private-ns/private-kind/private-name", 599, "other", "other"},
		{"PRIVATE", "/private-path?credential=private", 200, "other", "200"},
	} {
		request, _ := http.NewRequest(c.method, "https://api.invalid"+c.path, nil)
		method, resource, status := apiMetricLabels(request, &http.Response{StatusCode: c.code}, nil)
		wantMethod := c.method
		if wantMethod == "PRIVATE" {
			wantMethod = "OTHER"
		}
		if method != wantMethod || resource != c.resource || status != c.status {
			t.Fatalf("labels: %s %s %s", method, resource, status)
		}
		_, _, failed := apiMetricLabels(request, nil, errors.New("private transport detail"))
		if failed != "transport_error" {
			t.Fatal(failed)
		}
	}
}

func TestAPIMetricsObserveTransportResult(t *testing.T) {
	request, _ := http.NewRequest("GET", "https://api.invalid/api/v1/namespaces/ns/pods", nil)
	counter := metrics.KubeAPIRequests.WithLabelValues("GET", "pods", "429")
	value := func() float64 {
		m := &dto.Metric{}
		if err := counter.Write(m); err != nil {
			t.Fatal(err)
		}
		return m.GetCounter().GetValue()
	}
	before := value()
	transport := measuredTransport{next: apiRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 429, Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	response, err := transport.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if got := value() - before; got != 1 {
		t.Fatal("missing server throttle observation", got)
	}
}
