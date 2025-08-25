FROM rust:1.88-bullseye AS build
COPY . /build
WORKDIR /build/
RUN cargo install --path drasyl-sp --features prometheus

FROM debian:bullseye-slim
COPY --from=build /usr/local/cargo/bin/drasyl-sp /usr/local/sbin/drasyl-sp
ENV DRASYL_UDP4_LISTEN=""
ENV DRASYL_UDP6_LISTEN="[::]:22527"
ENV DRASYL_TCP4_LISTEN=""
ENV DRASYL_TCP6_LISTEN="[::]:443"
ENV DRASYL_PROMETHEUS_LISTEN="[::]:9898"
EXPOSE 22527/udp 8443/tcp 9898/tcp
WORKDIR /drasyl/
ENTRYPOINT ["/usr/local/sbin/drasyl-sp"]
