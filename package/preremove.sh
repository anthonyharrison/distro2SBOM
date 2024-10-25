#!/bin/sh
set -eux

PIP="pip"
if command -v "pip3" >/dev/null 2>&1 ; then
    PIP="pip3"
fi
if ! command -v "$PIP" >/dev/null 2>&1 ; then
    echo "ERROR: no pip command found"
    exit 1
fi

"$PIP" uninstall -r /opt/distro2sbom/requirements.txt