FROM rust:1.88-bullseye AS build
COPY . /build
WORKDIR /build/
RUN cargo install --path netsody-sp --features prometheus

FROM debian:bullseye-slim
COPY --from=build /usr/local/cargo/bin/netsody-sp /usr/local/sbin/netsody-sp
ENV NETSODY_UDP4_LISTEN=""
ENV NETSODY_UDP6_LISTEN="[::]:22527"
ENV NETSODY_TCP4_LISTEN=""
ENV NETSODY_TCP6_LISTEN="[::]:443"
ENV NETSODY_PROMETHEUS_LISTEN="[::]:9898"
EXPOSE 22527/udp 8443/tcp 9898/tcp
WORKDIR /netsody/
ENTRYPOINT ["/usr/local/sbin/netsody-sp"]
