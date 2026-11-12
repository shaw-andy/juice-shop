#!/bin/sh

#
# Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
# SPDX-License-Identifier: MIT
#

# Exit on error
set -e

# Add docker key and repository
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo bash -c 'echo "deb [arch=$(dpkg --print-architecture)] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker-ce.list'


# Install apache and docker
apt-get update -q
apt-get upgrade -qy
apt-get install -qy apache2 docker-ce

# Put the relevant files in place
cp /tmp/juice-shop/default.conf /etc/apache2/sites-available/000-default.conf

# Download and start docker image with Juice Shop
# Pinned by digest so the shop cannot change when a tag is moved; update deliberately.
JUICE_SHOP_IMAGE=bkimminich/juice-shop@sha256:877fc77b12d72b42e486eb09b6b1711cc56514306d92006b284e7e7cf076a809
docker pull "$JUICE_SHOP_IMAGE"
docker run --restart=always -d -p 3000:3000 --name juice-shop "$JUICE_SHOP_IMAGE"

# Enable proxy modules in apache and restart
a2enmod proxy_http
systemctl restart apache2.service
