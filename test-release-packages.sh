#!/bin/bash
set -eux
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
# Verify package install for a release version

if [[ -f "$SCRIPT_DIR/.env" ]]; then
    # shellcheck disable=SC1091
    source "$SCRIPT_DIR/.env"
fi

CONTAINER_RUNTIME=${CONTAINER_RUNTIME:-docker}

APT_TARGETS=("ubuntu:20.04"
    "ubuntu:22.04"
    "debian:10"
    "debian:11")

# https://github.com/anthonyharrison/distro2SBOM/issues/4
YUM_TARGETS=("quay.io/centos/centos:stream9"
    "amazonlinux:2"
    "amazonlinux:2023")

for IMAGE in "${APT_TARGETS[@]}"
do
    echo "Testing $IMAGE"
    SBOM_NAME="${IMAGE%%:*}"
    SBOM_RELEASE="${IMAGE#*:}"

    $CONTAINER_RUNTIME run --rm -t \
        -v "$SCRIPT_DIR/package/output/":/package/:ro \
        -v "$SCRIPT_DIR/output/":/output/:rw \
        "$IMAGE" \
        sh -c  "apt-get update && apt-get install -y gpg curl /package/*.deb && \
                distro2sbom --help && \
                curl -sSfL https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh|sh &&
                echo distro2sbom -p fluent-bit --distro rpm --name ${SBOM_NAME} --release ${SBOM_RELEASE} --sbom cyclonedx --format json --output-file /output/${IMAGE/:/_}.json"
done

for IMAGE in "${YUM_TARGETS[@]}"
do
    echo "Testing $IMAGE"
    SBOM_NAME="${IMAGE%%:*}"
    SBOM_RELEASE="${IMAGE#*:}"

    $CONTAINER_RUNTIME run --rm -t \
        -v "$SCRIPT_DIR/package/output/":/package/:ro \
        -v "$SCRIPT_DIR/output/":/output/:rw \
        "$IMAGE" \
        sh -c  "yum install -y /package/*.rpm && \
                distro2sbom --help && \
                curl -sSfL https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh|sh && \
                echo distro2sbom -p fluent-bit --distro rpm --name ${SBOM_NAME} --release ${SBOM_RELEASE} --sbom cyclonedx --format json --output-file /output/${IMAGE/:/_}.json"
done

# TODO: consume output with Grype to generate CVEs
