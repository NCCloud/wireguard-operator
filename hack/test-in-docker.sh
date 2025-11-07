#!/usr/bin/env bash
set -euo pipefail

K8S_VERSION="${1:-1.30.0}"

# Ensure Go and Go bin are on PATH (golang base image)
export PATH="/usr/local/go/bin:/go/bin:${PATH}"

# Print versions for debugging
go version

rm -f ./bin/controller-gen ./bin/kustomize ./bin/setup-envtest ./bin/kind || true
make controller-gen kustomize envtest

# Download envtest assets and export KUBEBUILDER_ASSETS
ASSETS_PATH=$(./bin/setup-envtest use "${K8S_VERSION}" -p path)
export KUBEBUILDER_ASSETS="${ASSETS_PATH}"
export ENVTEST="$(pwd)/bin/setup-envtest"

echo "Using KUBEBUILDER_ASSETS=${KUBEBUILDER_ASSETS}"

# Run gen + linters
make manifests generate fmt vet

# Run unit + envtest suites verbosely (exclude e2e which require -tags=e2e)
go test -v -count=1 ./... -coverprofile cover.out

