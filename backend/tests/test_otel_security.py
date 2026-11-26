"""Patched OTel dependency graph, propagation bound and shipped instrumentors."""

import asyncio
from importlib import metadata
from pathlib import Path
import subprocess
import sys

from packaging.requirements import Requirement
from packaging.version import Version


def test_otel_security_floor_and_installed_dependency_graph():
    requirements = Path(__file__).resolve().parents[1] / "requirements.txt"
    pins = [
        Requirement(line)
        for line in requirements.read_text().splitlines()
        if line.startswith("opentelemetry-")
    ]
    api = next(pin for pin in pins if pin.name == "opentelemetry-api")
    assert all(spec.operator == "==" for pin in pins for spec in pin.specifier)
    assert Version(next(iter(api.specifier)).version) >= Version("1.45.2")
    for pin in pins:
        assert metadata.version(pin.name) in pin.specifier
        for text in metadata.requires(pin.name) or []:
            dependency = Requirement(text)
            if dependency.marker and not dependency.marker.evaluate({"extra": ""}):
                continue
            if dependency.name.startswith("opentelemetry-"):
                assert metadata.version(dependency.name) in dependency.specifier, text


def test_oversized_tracestate_has_bounded_parsing_and_preserves_traceparent():
    # The vulnerable regexp takes quadratic time on this whitespace run. Keep
    # the public propagation check in a bounded child so a downgrade cannot
    # wedge a test worker. This is a hang bound, not a performance benchmark.
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from opentelemetry.trace import get_current_span\n"
            "from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator\n"
            "carrier={'traceparent':'00-0123456789abcdef0123456789abcdef-0123456789abcdef-01',"
            "'tracestate':'a=b'+'\\t'*(1024*1024)+'x'}\n"
            "context=TraceContextTextMapPropagator().extract(carrier)\n"
            "span=get_current_span(context).get_span_context()\n"
            "assert span.is_valid and span.trace_id==int('0123456789abcdef0123456789abcdef',16)\n"
            "assert len(span.trace_state)==0\n",
        ],
        capture_output=True,
        text=True,
        timeout=5,
    )
    assert result.returncode == 0, result.stderr[-2000:]


def test_shipped_otel_instrumentors_and_http_exporter_work_together():
    import httpx
    from fastapi import FastAPI
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
    from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
    from opentelemetry.instrumentation.logging import LoggingInstrumentor
    from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )
    from opentelemetry.trace import SpanKind
    from sqlalchemy import create_engine, text

    provider = TracerProvider()
    spans = InMemorySpanExporter()
    provider.add_span_processor(SimpleSpanProcessor(spans))
    app = FastAPI()

    @app.get("/otel-check")
    async def healthy():
        return {"ok": True}

    FastAPIInstrumentor.instrument_app(app, tracer_provider=provider)
    engine = create_engine("sqlite://")
    database = SQLAlchemyInstrumentor()
    database.instrument(engine=engine, tracer_provider=provider)
    logs = LoggingInstrumentor()
    logs.instrument(set_logging_format=False, tracer_provider=provider)
    exporter = OTLPSpanExporter(endpoint="http://127.0.0.1:4318/v1/traces")

    trace_id = "0123456789abcdef0123456789abcdef"
    span_id = "0123456789abcdef"
    parent = f"00-{trace_id}-{span_id}-01"
    future_parent_prefix = f"01-{trace_id}-{span_id}-01-"
    oversized_parent = future_parent_prefix.ljust(513, "a")

    async def request(traceparent):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://otel.test"
        ) as client:
            response = await client.get(
                "/otel-check", headers={"traceparent": traceparent}
            )
            assert response.status_code == 200 and response.json() == {"ok": True}

    try:
        asyncio.run(request(parent))
        asyncio.run(request(oversized_parent))
        # Model an outbound request separately: instrumenting an in-process
        # ASGI client suppresses nested instrumentation in that same context.
        with httpx.Client(
            transport=httpx.MockTransport(lambda request: httpx.Response(200))
        ) as client:
            HTTPXClientInstrumentor.instrument_client(client, tracer_provider=provider)
            try:
                assert client.get("http://outbound.test/check").status_code == 200
            finally:
                HTTPXClientInstrumentor.uninstrument_client(client)
        with engine.connect() as connection:
            assert connection.execute(text("SELECT 1")).scalar() == 1
        server_spans = [
            span for span in spans.get_finished_spans() if span.kind == SpanKind.SERVER
        ]
        assert len(server_spans) == 2
        assert server_spans[0].parent.trace_id == int(trace_id, 16)
        assert server_spans[0].parent.span_id == int(span_id, 16)
        assert server_spans[1].parent is None
        assert any(
            span.kind == SpanKind.CLIENT
            and span.attributes.get("http.url") == "http://outbound.test/check"
            for span in spans.get_finished_spans()
        )
        assert any(
            span.attributes.get("db.system") == "sqlite"
            for span in spans.get_finished_spans()
        )
    finally:
        exporter.shutdown()
        logs.uninstrument()
        database.uninstrument()
        FastAPIInstrumentor.uninstrument_app(app)
        engine.dispose()
        provider.shutdown()
