#!/bin/bash
set -eux
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if ! command -v nfpm &> /dev/null; then
    echo "Missing nfpm command: https://nfpm.goreleaser.com/"
    exit 1
fi

# The architecture to build for
export ARCH=${ARCH:-amd64}
# The package version
export VERSION=${VERSION:-1.0.0}
# Where to put the packages
OUTPUT_DIR=${OUTPUT_DIR:-$SCRIPT_DIR/output}

# Allow us to cope with any architecture via simple substitution
# shellcheck disable=SC2016
envsubst '$ARCH,$VERSION' < "$SCRIPT_DIR/nfpm-template.yaml" > "$SCRIPT_DIR/nfpm.yaml"

# Need to be in the right directory for relative paths in the template
pushd "$SCRIPT_DIR"
nfpm package --config "$SCRIPT_DIR/nfpm.yaml" --packager apk --target "$OUTPUT_DIR"
nfpm package --config "$SCRIPT_DIR/nfpm.yaml" --packager deb --target "$OUTPUT_DIR"
nfpm package --config "$SCRIPT_DIR/nfpm.yaml" --packager rpm --target "$OUTPUT_DIR"
popd