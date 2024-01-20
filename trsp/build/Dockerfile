FROM rust:1.70-slim-bullseye AS build

RUN \
    apt-get update \
    && apt-get install -y pkg-config libssl-dev nodejs npm

WORKDIR /build
RUN USER=root cargo new --bin trsp && mkdir ./trsp/front
COPY code/Cargo.toml code/Cargo.lock code/build.rs ./trsp/
WORKDIR /build/trsp
RUN SKIP_CBINDGEN=1 cargo build --release
COPY code/front/package.json code/front/package-lock.json
RUN cargo build --release

COPY code .
RUN cargo build --release


FROM debian:bullseye-slim
ARG S6_OVERLAY_VERSION=3.1.5.0

ARG WIREGUARD_RELEASE

ENV DEBIAN_FRONTEND="noninteractive"

RUN \
    apt-get update \
    && apt-get install -y curl wget xz-utils procps \
    cron \
    wireguard \
    wireguard-tools \
    iptables \
    iproute2 \
    dnsutils \
    shadowsocks-libev \
    && wget -O /tmp/s6-overlay-noarch.tar.xz https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz \
    && wget -O /tmp/s6-overlay-x86_64.tar.xz https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-x86_64.tar.xz \
    && tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz \
    && tar -C / -Jxpf /tmp/s6-overlay-x86_64.tar.xz \
    && ln -s /command/* /bin/ \
    && apt-get -y remove xz-utils wget \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*



COPY build/etc/cont-init.d /etc/cont-init.d
RUN find /etc/cont-init.d -exec chmod ug+x {} \;
COPY build/etc/services.d /etc/services.d
RUN find /etc/services.d -exec chmod ug+x {} \;
COPY build/opt/wireguard /opt/wireguard
COPY build/etc/crontab /etc/crontab

VOLUME /opt/wireguard/config
VOLUME /opt/trsp/

COPY --from=build /build/trsp/target/release/trsp /bin/trsp
#RUN chmod +x /bin/trsp

ENTRYPOINT ["/init"]


