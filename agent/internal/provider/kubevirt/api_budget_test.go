//go:build kubevirt

package kubevirt

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/flowcontrol"
)

type countedLimiter struct {
	flowcontrol.RateLimiter
	waits atomic.Int32
}

func (l *countedLimiter) Wait(ctx context.Context) error {
	l.waits.Add(1)
	return l.RateLimiter.Wait(ctx)
}

func TestTypedAndDynamicClientsShareBudgetAndRespectCancellation(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"test"}}`))
	}))
	defer server.Close()
	cfg := &rest.Config{Host: server.URL}
	if err := configureAPIBudget(cfg, 50, 100); err != nil {
		t.Fatal(err)
	}
	limiter := &countedLimiter{RateLimiter: cfg.RateLimiter}
	cfg.RateLimiter = limiter
	typed, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = typed.CoreV1().Namespaces().Get(context.Background(), "test", metav1.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	resource := dyn.Resource(schema.GroupVersionResource{Version: "v1", Resource: "namespaces"})
	if _, err = resource.Get(context.Background(), "test", metav1.GetOptions{}); err != nil {
		t.Fatal(err)
	}
	if limiter.waits.Load() != 2 || requests.Load() != 2 {
		t.Fatal("clients did not consume the same configured limiter", limiter.waits.Load(), requests.Load())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = resource.Get(ctx, "test", metav1.GetOptions{}); err == nil || requests.Load() != 2 {
		t.Fatal("dynamic client ignored cancellation", err, requests.Load())
	}
	if _, err = typed.CoreV1().Namespaces().Get(ctx, "test", metav1.GetOptions{}); err == nil || requests.Load() != 2 {
		t.Fatal("typed client bypassed shared budget/cancellation", err, requests.Load())
	}
}

func TestAPIBudgetRefusesUnboundedSettings(t *testing.T) {
	for _, values := range [][2]int{{0, 100}, {-1, 100}, {201, 400}, {50, 49}, {50, 401}} {
		if configureAPIBudget(&rest.Config{}, values[0], values[1]) == nil {
			t.Fatal("invalid budget", values)
		}
	}
}

type apiRoundTrip func(*http.Request) (*http.Response, error)

func (f apiRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestRequestDeadlineCoversBodyWithoutShorteningWatches(t *testing.T) {
	for _, query := range []string{"", "?watch=true", "?watch=1"} {
		var observed context.Context
		transport := measuredTransport{next: apiRoundTrip(func(r *http.Request) (*http.Response, error) {
			observed = r.Context()
			deadline, limited := observed.Deadline()
			if (query == "") != limited {
				t.Fatal("incorrect request/watch deadline", query, limited)
			}
			if limited && (time.Until(deadline) <= 0 || time.Until(deadline) > apiTimeout) {
				t.Fatal("unbounded ordinary request")
			}
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("body"))}, nil
		})}
		req, _ := http.NewRequest(http.MethodGet, "http://example.test/api/v1/pods"+query, nil)
		response, err := transport.RoundTrip(req)
		if err != nil || observed.Err() != nil {
			t.Fatal("body canceled at headers", err)
		}
		_ = response.Body.Close()
		if query == "" && observed.Err() == nil {
			t.Fatal("closed body retained request timer")
		}
	}
}
