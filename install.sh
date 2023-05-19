#!/usr/bin/env bash
set -e

echo "This script requires superuser access to install packages."
echo "You will be prompted for your password by sudo."

# Determine package type to install: https://unix.stackexchange.com/a/6348
# OS used by all - for Debs it must be Ubuntu or Debian
# CODENAME only used for Debs
if [ -f /etc/os-release ]; then
    # Debian uses Dash which does not support source
    # shellcheck source=/dev/null
    . /etc/os-release
    OS=$( echo "${ID}" | tr '[:upper:]' '[:lower:]')
elif lsb_release &>/dev/null; then
    OS=$(lsb_release -is | tr '[:upper:]' '[:lower:]')
else
    OS=$(uname -s)
fi

SUDO=sudo
if [ "$(id -u)" -eq 0 ]; then
    SUDO=''
else
    # Clear any previous sudo permission
    sudo -k
fi

# Now set up repos and install dependent on OS, version, etc.
# Will require sudo
case ${OS} in
    amzn|amazonlinux|centos|centoslinux|rhel|redhatenterpriselinuxserver|fedora|rocky|almalinux)
        # We need variable expansion and non-expansion on the URL line to pick up the base URL.
        # Therefore we combine things with sed to handle it.
        $SUDO yum install -y python3
    ;;
    ubuntu|debian)
        # Remember apt-key add is deprecated
        # https://wiki.debian.org/DebianRepository/UseThirdParty#OpenPGP_Key_distribution
        $SUDO apt-get -y update
        $SUDO apt-get -y install python3
    ;;
    *)
        echo "${OS} not supported."
        exit 1
    ;;
esac

$SUDO python -m ensurepip --upgrade
pip install distro2sbom

echo ""
echo "Installation completed."
echo ""
