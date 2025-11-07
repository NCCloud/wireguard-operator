ARG WIREGUARD_GO_SRC=/usr/local/src/wireguard-go
ARG WIREGUARD_AGENT_SRC=/usr/local/src/wireguard-agent
ARG PROMETHEUS_WIREGUARD_EXPORTER_SRC=/usr/local/src/prometheus-wireguard-exporter

# step 1: Build Agent
FROM --platform=${BUILDPLATFORM} golang:1.25 AS golang-builder
ARG WIREGUARD_AGENT_SRC
WORKDIR $WIREGUARD_AGENT_SRC
# Ensure newer toolchains can be auto-fetched if needed
ENV GOTOOLCHAIN=auto
# Copy the Go Modules manifests
COPY go.mod go.mod
COPY go.sum go.sum
# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download
# COPY src
COPY api/ api/
COPY cmd/ cmd/
COPY internal/ internal/
# build
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o agent -x cmd/agent/main.go
# end of step 1

# step 2: Build wireguard-go
ARG WIREGUARD_GO_SRC
WORKDIR $WIREGUARD_GO_SRC
RUN set -eux; \
    git clone https://github.com/WireGuard/wireguard-go.git . ;\
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -o wireguard-go ;
# end of step 2

# step 3: prepare image
FROM debian:trixie
ARG WIREGUARD_GO_SRC
ARG WIREGUARD_AGENT_SRC
ARG PROMETHEUS_WIREGUARD_EXPORTER_SRC

RUN apt-get update \
    && apt-get install --no-install-recommends -y iptables wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

COPY --from=golang-builder $WIREGUARD_GO_SRC/wireguard-go /usr/local/bin
COPY --from=golang-builder $WIREGUARD_AGENT_SRC/agent /usr/local/bin

WORKDIR /

ENTRYPOINT ["agent"]
# end of step 3
