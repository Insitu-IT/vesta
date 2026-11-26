FROM python:3.11-slim

WORKDIR /app
ENV VNBUI_ARTIFACT_EDITION=community
COPY LICENSE /usr/share/licenses/vnbui/LICENSE
COPY NOTICE /usr/share/licenses/vnbui/NOTICE
LABEL org.opencontainers.image.licenses="LicenseRef-Vesta-MMIT-1.1"
COPY registration-trust.json /etc/vnbui/license-keys.json

# Install dependencies
COPY requirements.txt .
COPY scripts/prune-reportlab-fonts.py /tmp/prune-reportlab-fonts.py
COPY scripts/retain-pip-provenance.py /tmp/retain-pip-provenance.py
COPY scripts/bind-psycopg2-native-notices.py /tmp/bind-psycopg2-native-notices.py
COPY notices/psycopg2-native/ /usr/share/licenses/vnbui/psycopg2-native/
# Dependency wheels can include development guidance. Remove it before this
# layer is committed, retaining runtime code and third-party license notices.
RUN pip install --no-cache-dir --report /tmp/vesta-pip-install.json -r requirements.txt \
    && python /tmp/retain-pip-provenance.py /tmp/vesta-pip-install.json /usr/share/licenses/vnbui/python-installation.json \
    && python /tmp/bind-psycopg2-native-notices.py /usr/share/licenses/vnbui/python-installation.json /usr/share/licenses/vnbui/psycopg2-native \
    && python /tmp/prune-reportlab-fonts.py \
    && rm /tmp/prune-reportlab-fonts.py /tmp/retain-pip-provenance.py /tmp/bind-psycopg2-native-notices.py \
    && find /usr/local/lib/python3.11/site-packages -type d -name .agents -prune -exec rm -rf -- '{}' +

# Explicit interpreted runtime inventory; never copy the development checkout.
COPY app.py api_docs.py config.py database.py deps.py exceptions.py logging_config.py \
    manage_admin.py middleware.py models.py scheduler.py server.py validators.py \
    version.py operator_contracts.py operator_admission_contracts.py \
    operator_protocol_contracts.py operator_surface_contracts.py \
    operator_resource_contracts.py operator_restore_contracts.py operator_error_contracts.py \
    operator_schema_inventory.py alembic.ini ./
COPY core/ core/
COPY routers/ routers/
COPY schemas/ schemas/
COPY services/ services/
COPY utils/ utils/
COPY demo/ demo/
COPY alembic/ alembic/
COPY static/api-docs/ static/api-docs/
COPY notices/api-docs/ /usr/share/licenses/vnbui/api-docs/

# Expose port
EXPOSE 8000

# APM / OpenTelemetry (Stage 1 — #33): off-by-default so local dev and any run
# without the APM server is a clean no-op. The deployment sets
# OTEL_TRACES_EXPORTER=otlp, OTEL_EXPORTER_OTLP_PROTOCOL=http/protobuf and
# OTEL_EXPORTER_OTLP_ENDPOINT to enable trace export. Stage 1 does not export
# metrics or logs through OTel.
ENV OTEL_TRACES_EXPORTER=none
ENV OTEL_METRICS_EXPORTER=none
ENV OTEL_LOGS_EXPORTER=none

# Run application under the OTel auto-instrumentation wrapper (zero app-code):
# opentelemetry-instrument reads the OTEL_* env and auto-instruments FastAPI,
# SQLAlchemy and httpx. All exporters are disabled by default.
CMD ["opentelemetry-instrument", "python", "server.py"]
