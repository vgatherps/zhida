# The Zhida test image plus nftables, for make docker-binance (NAT from the
# net_tap netdev out of the container's eth0).
ARG BASE=zhida-dpdk-test:local
FROM ${BASE}
RUN apt-get update && apt-get install -y --no-install-recommends nftables \
    && rm -rf /var/lib/apt/lists/*
