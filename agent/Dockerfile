FROM golang:1.26.11-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
RUN GOBIN=/usr/local/bin go install github.com/google/go-licenses/v2@v2.0.1

COPY . .
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$(cat VERSION)" \
    -o /runtime/vesta-agent ./cmd/vnbui-agent
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=$(cat VERSION)" \
    -o /runtime/vesta-restore ./cmd/vnbui-restore
RUN mkdir -p /runtime/opt/vnbui-agent && \
    ln -s /vesta-agent /runtime/opt/vnbui-agent/vnbui-agent && \
    ln -s /opt/vesta-agent/VERSION /runtime/opt/vnbui-agent/VERSION
RUN sh scripts/collect-third-party-notices.sh /third-party-notices default "$(go env GOROOT)/LICENSE"

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -u 1001 agentuser && \
    mkdir -p /var/lib/vnbui/backups && \
    chown -R agentuser:root /var/lib/vnbui && \
    chmod -R g+rwX /var/lib/vnbui

COPY --from=builder /runtime/ /
COPY VERSION /opt/vesta-agent/VERSION
COPY LICENSE /usr/share/licenses/vnbui/LICENSE
COPY NOTICE /usr/share/licenses/vnbui/NOTICE
LABEL org.opencontainers.image.licenses="LicenseRef-Vesta-MMIT-1.1"
COPY --from=builder /third-party-notices/ /usr/share/licenses/vnbui/third-party/

USER 1001
EXPOSE 8090

ENTRYPOINT ["/vesta-agent"]
