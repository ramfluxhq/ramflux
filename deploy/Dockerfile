FROM debian:trixie-slim

ARG BIN
ENV RAMFLUX_BIN="${BIN}"

COPY target/release/${BIN} /usr/local/bin/${BIN}
RUN chmod +x "/usr/local/bin/${BIN}"

ENTRYPOINT ["/bin/sh", "-c", "exec /usr/local/bin/${RAMFLUX_BIN} \"$@\"", "--"]
