FROM debian:bullseye-slim
ARG S6_OVERLAY_VERSION=3.1.0.1

RUN \
    apt-get update \
    && apt-get install -y curl \
    && curl https://secure.nic.cz/files/knot-resolver/knot-resolver-release.deb -o knot-resolver-release.deb \
    && dpkg -i knot-resolver-release.deb \
    && apt-get update \
    && apt -o Dpkg::Options::="--force-confold" -y full-upgrade \
    && rm -f knot-resolver-release.deb \
    && apt-get install -y \
    iptables \
    iproute2 \
    git \
    python3 \
    knot-resolver \
    inetutils-ping \
    python3-dnslib \
    gawk \
    dnsutils \
    procps \
    wget \
    cron \
    ipcalc \
    vim \
    xz-utils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz /tmp
ADD https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-x86_64.tar.xz /tmp
RUN \
    tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz \
    && tar -C / -Jxpf /tmp/s6-overlay-x86_64.tar.xz

RUN git clone https://bitbucket.org/anticensority/antizapret-pac-generator-light.git /antizapret

RUN \
    mkdir -p /etc/knot-resolver/aliases \
    && mkdir -p /var/lib/knot-resolver/storage \
    && mkdir -p /run/knot-resolver \
    && chown knot-resolver:knot-resolver /run/knot-resolver \
    && chmod 0770 /run/knot-resolver \
    && mkdir /tmp/knot-resolver \
    && chown knot-resolver:knot-resolver /tmp/knot-resolver \
    && chmod 0770 /tmp/knot-resolver \
    && chown -R knot-resolver:knot-resolver /var/lib/knot-resolver \
    && chmod -R 0770 /var/lib/knot-resolver

COPY etc/knot/kresd.conf /etc/knot-resolver/kresd.conf
COPY etc/knot/aliases.conf /knot_aliases_default.conf

COPY opt/dnsmap /opt/dnsmap

COPY etc/services.d /etc/services.d
RUN find /etc/services.d -name run -exec chmod ug+x {} \;

RUN \
    chmod +x /opt/dnsmap/proxy.py \
    && chmod +x /opt/dnsmap/*.sh




ENTRYPOINT ["/init"]


