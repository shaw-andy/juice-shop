#!/bin/sh

#
# Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
# SPDX-License-Identifier: MIT
#

# Exit on error
set -e

DOCKER_KEY_FINGERPRINT=9DC858229FC7DD38854AE2D88D81803C0EBFCD88
DOCKER_KEYRING=/etc/apt/keyrings/docker.gpg
CODENAME=$(lsb_release -cs)
DOCKER_VERSION="5:20.10.17~3-0~ubuntu-$CODENAME"

# Upgrade from the distribution repositories before the docker repository is added
apt-get update -q
apt-get upgrade -qy

# Add docker key and repository
KEY_DIR=$(mktemp -d)
trap 'rm -rf "$KEY_DIR"' EXIT
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o "$KEY_DIR/docker.asc"
gpg --batch --quiet --homedir "$KEY_DIR" --import "$KEY_DIR/docker.asc"
gpg --batch --homedir "$KEY_DIR" --export "$DOCKER_KEY_FINGERPRINT" > "$KEY_DIR/docker.gpg"
KEYRING_FINGERPRINTS=$(gpg --batch --homedir "$KEY_DIR" --with-colons --show-keys "$KEY_DIR/docker.gpg" | awk -F: '$1 == "pub" { pub = 1; next } pub && $1 == "fpr" { print $10; pub = 0 }')
if [ "$KEYRING_FINGERPRINTS" != "$DOCKER_KEY_FINGERPRINT" ]; then
  echo "Docker apt signing key does not match fingerprint $DOCKER_KEY_FINGERPRINT" >&2
  exit 1
fi
install -d -m 0755 "$(dirname "$DOCKER_KEYRING")"
install -m 0644 "$KEY_DIR/docker.gpg" "$DOCKER_KEYRING"
echo "deb [arch=$(dpkg --print-architecture) signed-by=$DOCKER_KEYRING] https://download.docker.com/linux/ubuntu $CODENAME stable" > /etc/apt/sources.list.d/docker-ce.list
cat > /etc/apt/preferences.d/docker-ce <<'EOF'
Package: containerd.io docker-ce docker-ce-cli docker-ce-rootless-extras docker-compose-plugin docker-scan-plugin
Pin: origin download.docker.com
Pin-Priority: 500

Package: *
Pin: origin download.docker.com
Pin-Priority: -1
EOF

# Install apache and docker
apt-get update -q
apt-get install -qy apache2 "docker-ce=$DOCKER_VERSION" "docker-ce-cli=$DOCKER_VERSION"

# Put the relevant files in place
cp /tmp/juice-shop/default.conf /etc/apache2/sites-available/000-default.conf

# Download and start docker image with Juice Shop
docker run --restart=always -d -p 3000:3000 --name juice-shop bkimminich/juice-shop

# Enable proxy modules in apache and restart
a2enmod proxy_http
systemctl restart apache2.service
