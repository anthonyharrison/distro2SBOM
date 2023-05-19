#!/bin/bash
set -eux
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if ! command -v nfpm &> /dev/null; then
    echo "Missing nfpm command: https://nfpm.goreleaser.com/"
    exit 1
fi

OUTPUT_DIR=${OUTPUT_DIR:-$SCRIPT_DIR/output}

pushd "$SCRIPT_DIR"
nfpm package --config "$SCRIPT_DIR/nfpm.yaml" --packager apk --target "$OUTPUT_DIR"
nfpm package --config "$SCRIPT_DIR/nfpm.yaml" --packager deb --target "$OUTPUT_DIR"
nfpm package --config "$SCRIPT_DIR/nfpm.yaml" --packager rpm --target "$OUTPUT_DIR"
popd