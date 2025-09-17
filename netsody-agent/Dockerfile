FROM rust:1.86-bullseye AS build
COPY . /build
WORKDIR /build/
RUN cargo install --path netsody-agent

FROM debian:bullseye-slim
COPY --from=build /usr/local/cargo/bin/netsody /usr/local/bin/netsody
ENV NETSODY_UDP_PORT="22527"
ENV NETSODY_API_LISTEN="0.0.0.0:22527"
EXPOSE 22527/udp 22527/tcp
WORKDIR /netsody/
ENTRYPOINT ["/usr/local/bin/netsody"]