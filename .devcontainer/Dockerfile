FROM debian:bookworm-slim

ARG ZIG_VERSION=0.17.0
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates git python3 xz-utils \
    && rm -rf /var/lib/apt/lists/*
COPY .devcontainer/install-zig.py /tmp/install-zig.py
RUN python3 /tmp/install-zig.py "$ZIG_VERSION" && rm /tmp/install-zig.py \
    && useradd --create-home --uid 1000 developer
ENV PATH="/opt/zig:${PATH}"
USER developer
