FROM golang:1.25

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git curl bash && rm -rf /var/lib/apt/lists/*

# setup-envtest to fetch apiserver/etcd assets
RUN go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

WORKDIR /workspace

# Warm module cache (optional)
COPY go.mod go.sum ./
RUN go mod download

# We run tests with bind-mounted source, not copying sources into the image

# No entrypoint; caller will invoke /bin/bash explicitly

