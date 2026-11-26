package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// initOTel sets up OpenTelemetry tracing with an OTLP/HTTP exporter pointing at
// OTEL_EXPORTER_OTLP_ENDPOINT (terminated by the Elastic APM server's native OTLP
// receiver). Returns a shutdown closure that flushes pending spans.
//
// When OTEL_EXPORTER_OTLP_ENDPOINT is unset the call is a complete no-op: no
// exporter is built, no tracer provider is installed (otel.GetTracerProvider
// stays at the global noop), no batcher goroutine starts, and no DNS lookup is
// ever attempted. The otelhttp wrappers degrade to silent pass-throughs against
// the noop provider. This matters because the vnbui agent deploys on customer
// sites where APM is usually off (and often air-gapped) — Stage 1 is exactly the
// plumbing that makes per-deployment endpoints possible without forcing egress.
// Mirrors iris-collector/cmd/iris-collector/otel.go and the cfg.Enabled gates in
// the oogl-* services.
//
// Service-name precedence:
//  1. OTEL_SERVICE_NAME env (standard OTel convention)
//  2. defaultName argument ("vesta-agent")
//
// deployment.environment / service.version come from OTEL_RESOURCE_ATTRIBUTES via
// resource.WithFromEnv() — set at the deployment layer, not baked into defaults.
//
// Direction: moray-docs/docs/directions/apm-instrumentation.md (Stage 1) +
// apm-otlp-strategy-note.md — new Go instrumentation goes OTel/OTLP-direct;
// correlation with native Elastic APM agents elsewhere is via W3C Trace Context.
func initOTel(defaultName string, log *slog.Logger) (func(context.Context) error, error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		log.Info("otel: OTEL_EXPORTER_OTLP_ENDPOINT not set; tracing disabled")
		return func(context.Context) error { return nil }, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// otlptracehttp reads endpoint / TLS / headers from the standard OTEL_* env
	// vars — no per-deployment Go-side config beyond the env block.
	exp, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("otel: exporter init: %w", err)
	}

	svcName := os.Getenv("OTEL_SERVICE_NAME")
	if svcName == "" {
		svcName = defaultName
	}

	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithAttributes(
			semconv.ServiceName(svcName),
			semconv.ServiceNamespace("vesta"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("otel: resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	// W3C Trace Context is interop-compatible with the Elastic native APM agents
	// elsewhere in the platform (iris-core, oogl-*) and with the vnbui backend's
	// OTel export — the same traceparent header crosses the OTel<->native and
	// browser-RUM<->service boundaries in both directions.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	log.Info("otel: tracing enabled",
		"endpoint", endpoint,
		"service", svcName,
		"namespace", "vesta",
	)
	return tp.Shutdown, nil
}
