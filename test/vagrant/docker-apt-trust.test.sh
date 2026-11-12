#!/bin/sh

#
# Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
# SPDX-License-Identifier: MIT
#

cd "$(dirname "$0")/../.." || exit 2
exec python3 test/vagrant/docker_apt_trust_test.py
