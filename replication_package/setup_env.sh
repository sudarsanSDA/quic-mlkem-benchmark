#!/usr/bin/env bash
set -euo pipefail

# Provision dependencies for genuine FIPS 203 ML-KEM over QUIC benchmarking on Ubuntu/Debian.
echo "Updating package lists..."
apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    tcpdump \
    tshark \
    python3 \
    python3-pip \
    python3-venv \
    openssl \
    ca-certificates \
    git \
    build-essential \
    cmake \
    ninja-build \
    libssl-dev

LIBOQS_TAG="${LIBOQS_TAG:-0.12.0}"
OQS_BUILD_DIR="/tmp/liboqs-src"

if ! ldconfig -p | grep -q "liboqs.so"; then
    echo "Building C liboqs (${LIBOQS_TAG}) with ML-KEM enabled..."
    rm -rf "${OQS_BUILD_DIR}"
    git clone --depth 1 --branch "${LIBOQS_TAG}" https://github.com/open-quantum-safe/liboqs.git "${OQS_BUILD_DIR}"
    cmake -S "${OQS_BUILD_DIR}" -B "${OQS_BUILD_DIR}/build" -GNinja \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_DIST_BUILD=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local
    ninja -C "${OQS_BUILD_DIR}/build"
    ninja -C "${OQS_BUILD_DIR}/build" install
    rm -rf "${OQS_BUILD_DIR}"
fi

echo "/usr/local/lib" > /etc/ld.so.conf.d/liboqs.conf
ldconfig

VENV_DIR="${VENV_DIR:-.venv}"
if [ ! -d "${VENV_DIR}" ]; then
    python3 -m venv "${VENV_DIR}"
fi

"${VENV_DIR}/bin/pip" install --upgrade pip setuptools wheel
"${VENV_DIR}/bin/pip" install \
    aioquic \
    cryptography \
    "liboqs-python @ git+https://github.com/open-quantum-safe/liboqs-python.git@${LIBOQS_TAG}" \
    kyber-py \
    pytest \
    matplotlib \
    seaborn \
    pandas \
    numpy

echo "Running end-to-end cryptographic and tamper verification..."
"${VENV_DIR}/bin/python" verify_mlkem_integration.py --require-native-backend --microbench 100

echo "Environment setup complete. Activate with: source ${VENV_DIR}/bin/activate"
