#!/usr/bin/env bash
# Paquets Linux de tlsrelay, construits dans un conteneur de la distribution la
# plus ancienne visée (PLAN : Ubuntu 22.04, RHEL 9) : un paquet construit sur
# Ubuntu 22.04 s'installe aussi sur les versions suivantes et sur Debian 12.
# Dépendances embarquées (TLSRELAY_FETCH_DEPS), OpenSSL de la distribution ;
# toute la suite de tests est exécutée sur la distribution cible.
#
# Usage, depuis la racine du dépôt :
#   docker run --rm -v "$PWD:/src" -w /src ubuntu:22.04 packaging/build-linux.sh paquets
#   docker run --rm -v "$PWD:/src" -w /src rockylinux:9 packaging/build-linux.sh paquets
set -euo pipefail

out=$(realpath -m "${1:?répertoire de sortie}")
src=$(pwd)
build=/tmp/tlsrelay-build
mkdir -p "$out"
. /etc/os-release

case "$ID" in
  ubuntu|debian)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y -q --no-install-recommends gcc-12 g++-12 make git libssl-dev openssl dpkg-dev file \
      python3 python3-pip ca-certificates
    pip3 install -q 'cmake>=3.25,<3.31'  # Ubuntu 22.04 : CMake 3.22
    export CC=gcc-12 CXX=g++-12
    generator=DEB
    ;;
  rocky|rhel|almalinux|centos)
    dnf install -y -q gcc-toolset-13-gcc gcc-toolset-13-gcc-c++ make git openssl-devel openssl rpm-build cmake python3 file
    # GCC 13 ; le binaire n'exige que la bibliothèque C++ de base de la distribution.
    set +u; source /opt/rh/gcc-toolset-13/enable; set -u
    generator=RPM
    ;;
  *)
    echo "distribution non prise en charge : $ID" >&2
    exit 2
    ;;
esac

git config --global --add safe.directory "$src"
cmake -S "$src" -B "$build" -DCMAKE_BUILD_TYPE=Release -DTLSRELAY_FETCH_DEPS=ON -DTLSRELAY_WARNINGS_AS_ERRORS=ON
cmake --build "$build" -j "$(nproc)"
(cd "$build" && ctest --output-on-failure -j "$(nproc)")
(cd "$build" && cpack -G "$generator")
cp "$build"/*.deb "$build"/*.rpm "$out"/ 2>/dev/null || true
ls -l "$out"
