FROM rust:1.93.0-bookworm@sha256:d0a4aa3ca2e1088ac0c81690914a0d810f2eee188197034edf366ed010a2b382 AS rust

FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential make pkg-config clang-18 libclang-18-dev lld-18 \
    meson ninja-build python3-pyelftools libnuma-dev libpcap-dev curl ca-certificates iproute2 ethtool \
    && rm -rf /var/lib/apt/lists/* \
    && update-alternatives --install /usr/bin/clang clang /usr/bin/clang-18 100 \
    && update-alternatives --install /usr/bin/ld.lld ld.lld /usr/bin/ld.lld-18 100

RUN curl --fail --location --retry 2 -o /tmp/dpdk.tar.xz \
        https://fast.dpdk.org/rel/dpdk-25.11.3.tar.xz \
    && echo '3719acc586b310c4f60ba230683bf4f1e12c6f2f5bee11f7c01b1bbd0ded7490  /tmp/dpdk.tar.xz' | sha256sum --check \
    && mkdir /tmp/dpdk && tar -xJf /tmp/dpdk.tar.xz -C /tmp/dpdk --strip-components=1 \
    && CC=clang meson setup /tmp/dpdk/build /tmp/dpdk \
        --buildtype=release --prefix=/opt/dpdk --libdir=lib \
        -Dplatform=generic -Denable_stdatomic=false -Dmbuf_refcnt_atomic=false \
        -Denable_iova_as_pa=true -Dtests=false -Ddisable_apps='*' \
        -Denable_drivers=net/ring,net/pcap,net/tap,net/memif,net/af_packet,net/ena,net/intel/ixgbe,net/intel/i40e,net/intel/ice \
    && ninja -C /tmp/dpdk/build && meson install -C /tmp/dpdk/build \
    && rm -rf /tmp/dpdk /tmp/dpdk.tar.xz

COPY packetdrill-relearn-isn.patch /tmp/packetdrill-relearn-isn.patch
RUN apt-get update && apt-get install -y --no-install-recommends flex bison patch \
    && rm -rf /var/lib/apt/lists/* \
    && curl --fail --location --retry 2 -o /tmp/packetdrill.tar.gz \
        https://github.com/google/packetdrill/archive/83f72d3f9085d0e26eb4d206fe4d7cfab5b6d872.tar.gz \
    && echo '3f527b08eabc40c622d3f7426a0b594ad05e101788cd40f0039c21410a9dab6f  /tmp/packetdrill.tar.gz' | sha256sum --check \
    && mkdir /tmp/packetdrill && tar -xzf /tmp/packetdrill.tar.gz -C /tmp/packetdrill --strip-components=1 \
    && cd /tmp/packetdrill && patch -p1 < /tmp/packetdrill-relearn-isn.patch \
    && cd /tmp/packetdrill/gtests/net/packetdrill && ./configure && make -j"$(nproc)" CC=clang \
    && install -D -m 0755 packetdrill /opt/packetdrill/bin/packetdrill \
    && install -D -m 0644 packetdrill.h /opt/packetdrill/include/packetdrill.h \
    && cd / && rm -rf /tmp/packetdrill /tmp/packetdrill.tar.gz /tmp/packetdrill-relearn-isn.patch

RUN apt-get update && apt-get install -y --no-install-recommends python3-scapy \
    && rm -rf /var/lib/apt/lists/*

# Kernel-side load-latency client for the Zhida sockperf-compatible server.
RUN apt-get update && apt-get install -y --no-install-recommends autoconf automake libtool \
    && rm -rf /var/lib/apt/lists/* \
    && curl --fail --location --retry 2 -o /tmp/sockperf.tar.gz \
        https://github.com/Mellanox/sockperf/archive/refs/tags/3.10.tar.gz \
    && echo '5373385e78921ba7156e03629daa0a2243b388d4c2b0c8ff99218d2a3e3be7a1  /tmp/sockperf.tar.gz' | sha256sum --check \
    && mkdir /tmp/sockperf && tar -xzf /tmp/sockperf.tar.gz -C /tmp/sockperf --strip-components=1 \
    && cd /tmp/sockperf && ./autogen.sh && ./configure --prefix=/opt/sockperf && make -j"$(nproc)" && make install \
    && cd / && rm -rf /tmp/sockperf /tmp/sockperf.tar.gz

COPY --from=rust /usr/local/cargo /usr/local/cargo
COPY --from=rust /usr/local/rustup /usr/local/rustup
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/opt/packetdrill/bin:$PATH \
    PKG_CONFIG_PATH=/opt/dpdk/lib/pkgconfig \
    LD_LIBRARY_PATH=/opt/dpdk/lib \
    RUSTFLAGS="-C linker=clang -C link-arg=-fuse-ld=lld"
WORKDIR /work
CMD ["make", "help"]
