FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    LIBOQS_TAG=0.12.0 \
    VENV_DIR=/opt/venv \
    PATH="/opt/venv/bin:${PATH}" \
    LD_LIBRARY_PATH="/usr/local/lib"

RUN apt-get update && apt-get install -y --no-install-recommends \
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
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "${LIBOQS_TAG}" https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs-src \
    && cmake -S /tmp/liboqs-src -B /tmp/liboqs-src/build -GNinja \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_DIST_BUILD=ON \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
    && ninja -C /tmp/liboqs-src/build \
    && ninja -C /tmp/liboqs-src/build install \
    && echo "/usr/local/lib" > /etc/ld.so.conf.d/liboqs.conf \
    && ldconfig \
    && rm -rf /tmp/liboqs-src

RUN python3 -m venv "${VENV_DIR}" \
    && pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir \
        aioquic \
        cryptography \
        "liboqs-python @ git+https://github.com/open-quantum-safe/liboqs-python.git@${LIBOQS_TAG}" \
        kyber-py \
        pytest \
        matplotlib \
        seaborn \
        pandas \
        numpy

WORKDIR /workspace
COPY . /workspace

RUN chmod +x setup_env.sh apply_netem.sh netns_setup.sh netns_cleanup.sh run_revision_benchmarks.sh || true

# Self-check cryptographic integration during build (network namespaces require --privileged or CAP_NET_ADMIN at run time)
RUN python verify_mlkem_integration.py --require-native-backend --microbench 50

CMD ["/bin/bash"]

