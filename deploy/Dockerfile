FROM rust:1.96 AS source-build

ARG BIN
WORKDIR /workspace

COPY . .
RUN cargo build --locked --release --bin "${BIN}"

FROM debian:trixie-slim AS source-runtime

ARG BIN
ENV RAMFLUX_BIN="${BIN}"

COPY --from=source-build /workspace/target/release/${BIN} /usr/local/bin/${BIN}
RUN chmod +x "/usr/local/bin/${BIN}"

ENTRYPOINT ["/bin/sh", "-c", "exec /usr/local/bin/${RAMFLUX_BIN} \"$@\"", "--"]

FROM debian:trixie-slim AS prebuilt-runtime

ARG BIN
ENV RAMFLUX_BIN="${BIN}"

COPY target/release/${BIN} /usr/local/bin/${BIN}
RUN chmod +x "/usr/local/bin/${BIN}"

ENTRYPOINT ["/bin/sh", "-c", "exec /usr/local/bin/${RAMFLUX_BIN} \"$@\"", "--"]
