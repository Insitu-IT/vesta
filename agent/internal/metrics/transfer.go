package metrics

import "github.com/prometheus/client_golang/prometheus"

// Aggregate timings deliberately have no URL, object, tenant or credential
// labels. Throttle wait is separate from HTTP time to response headers.
var (
	KubeAPIThrottleSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "vnbui_agent_kube_api_throttle_seconds", Help: "Client-side Kubernetes API limiter wait", Buckets: prometheus.DefBuckets,
	})
	KubeAPIRequestSeconds = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name: "vnbui_agent_kube_api_request_seconds", Help: "Kubernetes HTTP request time to response headers, excluding limiter wait", Buckets: prometheus.DefBuckets,
	})
	KubeAPIRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vnbui_agent_kube_api_requests_total", Help: "Kubernetes HTTP results by bounded method, resource and status",
	}, []string{"method", "resource", "status"})
	KubeAPIResourceSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "vnbui_agent_kube_api_resource_seconds", Help: "Kubernetes HTTP header latency by bounded method/resource; excludes client limiter wait", Buckets: prometheus.DefBuckets,
	}, []string{"method", "resource"})
	StoragePartCycleSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "vnbui_agent_storage_part_cycle_seconds", Help: "Time between durable part acknowledgments, including source read, validation, encryption, upload and persistence; first cycle starts after multipart creation", Buckets: []float64{.01, .05, .1, .5, 1, 5, 15, 60, 300},
	}, []string{"role"})
	StorageUploadedBytes = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "vnbui_agent_storage_uploaded_bytes_total", Help: "Ciphertext bytes in acknowledged durably saved parts; not publication or checkpoint completion",
	}, []string{"role"})
	StorageStepSeconds = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "vnbui_agent_storage_step_seconds", Help: "Storage transaction step time; nested steps must not be summed", Buckets: []float64{.001, .01, .05, .1, .5, 1, 5, 15, 60, 300},
	}, []string{"step"})
)

func init() {
	Registry.MustRegister(KubeAPIThrottleSeconds, KubeAPIRequestSeconds, KubeAPIRequests, KubeAPIResourceSeconds, StorageStepSeconds, StoragePartCycleSeconds, StorageUploadedBytes)
}
