FROM rust:1.96 AS source-build

ARG BIN
WORKDIR /workspace

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .
RUN cargo build --locked --release --bin "${BIN}"

FROM debian:trixie-slim AS source-runtime

ARG BIN
ENV RAMFLUX_BIN="${BIN}"

COPY --from=source-build /workspace/target/release/${BIN} /usr/local/bin/${BIN}
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3t64 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && chmod +x "/usr/local/bin/${BIN}"
ENTRYPOINT ["/bin/sh", "-c", "exec /usr/local/bin/${RAMFLUX_BIN} \"$@\"", "--"]

FROM debian:trixie-slim AS prebuilt-runtime

ARG BIN
ENV RAMFLUX_BIN="${BIN}"

COPY target/release/${BIN} /usr/local/bin/${BIN}
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl3t64 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && chmod +x "/usr/local/bin/${BIN}"
ENTRYPOINT ["/bin/sh", "-c", "exec /usr/local/bin/${RAMFLUX_BIN} \"$@\"", "--"]
