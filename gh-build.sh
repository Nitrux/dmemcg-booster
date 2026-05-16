#!/usr/bin/env bash

set -euxo pipefail

### Basic Packages
apt -q update
apt -qq -yy install equivs git devscripts lintian build-essential ca-certificates --no-install-recommends

### Install Dependencies
mk-build-deps -i -t "apt-get --yes" -r

### Build Deb
debuild -b -uc -us

### Collect artifacts where workflow expects them
mkdir -p output
mv ../*.deb output/
