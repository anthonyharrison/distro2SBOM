#!/bin/sh
set -eux

PYTHON="python"
if command -v "python3" >/dev/null 2>&1 ; then
    PYTHON="python3"
fi
if ! command -v "$PYTHON" >/dev/null 2>&1 ; then
    echo "ERROR: no python command found"
    exit 1
fi

PIP="pip"
if command -v "pip3" >/dev/null 2>&1 ; then
    PIP="pip3"
fi
if ! command -v "$PIP" >/dev/null 2>&1 ; then
    echo "ERROR: no pip command found"
    exit 1
fi

"$PIP" install -U -r /opt/distro2sbom/requirements.txt

# Not install, it requires relative paths to work unfortunately
oldpath="$PWD"
cd /opt/distro2sbom/

"$PYTHON" setup.py install

cd "$oldpath"
