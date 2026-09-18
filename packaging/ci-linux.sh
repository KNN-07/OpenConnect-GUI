#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
set -eu
# Run ONLY inside packaging/Dockerfile.release, from the repository mount.
[ "$(. /etc/os-release; printf '%s' "$VERSION_ID")" = 22.04 ] || { echo 'Linux release build requires the Ubuntu 22.04 baseline image' >&2; exit 1; }
# The checkout is owned by the hosted runner, while this disposable build
# container runs as root. Trust only the explicitly mounted source directory.
git config --global --add safe.directory "$(pwd)"
curl --fail --location https://nodejs.org/dist/v22.19.0/node-v22.19.0-linux-x64.tar.xz -o /tmp/node.tar.xz
echo 'c0649af18e6a24f6fe5535a3e86b341dd49a8e71117c8b68bde973ef834f16f2  /tmp/node.tar.xz' | sha256sum -c -
tar -xJf /tmp/node.tar.xz -C /opt
export PATH=/opt/node-v22.19.0-linux-x64/bin:$PATH
npm install --global npm@11.19.0
rustup show active-toolchain
python3 native/prepare-linux-prefix.py /opt/ocvpn-deps
apt-get update
python3 packaging/freeze-linux-sources.py --prefix /opt/ocvpn-deps --output target/dependency-sources
export OCVPN_DEPENDENCY_SOURCES=target/dependency-sources
export RUSTFLAGS="--remap-path-prefix=$(pwd)=."
cargo xtask package --target x86_64-unknown-linux-gnu --dependency-prefix /opt/ocvpn-deps
