package api

import (
	"net/http"
	"slices"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"

	"vnbui/agent/internal/metrics"
)

// MetricsHandler exposes Vesta metric names alongside their existing aliases.
func MetricsHandler() http.Handler {
	gatherer := prometheus.GathererFunc(func() ([]*dto.MetricFamily, error) {
		families, err := metrics.Registry.Gather()
		for _, family := range families {
			suffix, ok := strings.CutPrefix(family.GetName(), "vnbui_")
			if !ok {
				continue
			}
			name := "vesta_" + suffix
			families = append(families, &dto.MetricFamily{
				Name:   &name,
				Help:   family.Help,
				Type:   family.Type,
				Metric: family.Metric,
				Unit:   family.Unit,
			})
		}
		slices.SortFunc(families, func(a, b *dto.MetricFamily) int {
			return strings.Compare(a.GetName(), b.GetName())
		})
		return families, err
	})
	return promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{})
}
