FROM debian:bullseye-slim
ARG S6_OVERLAY_VERSION=3.1.0.1
ARG WIREGUARD_RELEASE

ENV DEBIAN_FRONTEND="noninteractive"

# FOR KNOT
RUN \
    apt-get update \
    && apt-get install -y curl \
    && curl https://secure.nic.cz/files/knot-resolver/knot-resolver-release.deb -o knot-resolver-release.deb \
    && dpkg -i knot-resolver-release.deb \
    && apt-get update \
    && apt-get -o Dpkg::Options::="--force-confold" -y full-upgrade \
    && rm -f knot-resolver-release.deb \
    && apt-get install -y \
    iptables \
    iproute2 \
	ifupdown \
	iputils-ping \
	libc6 \
	libelf-dev \
	net-tools \
	openresolv \
	perl \
	pkg-config \
	qrencode \
	gnupg \
    git \
    python3 \
    python3-dnspython \
    python3-dnslib \
    knot-resolver \
    gawk \
    dnsutils \
    procps \
    wget \
    cron \
    ipcalc \
    vim \
    xz-utils \
    iputils-ping \
	bc \
	build-essential \
	dkms \
	jq \
    idn \
    sipcalc \
    wireguard \
    wireguard-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && wget -O /tmp/s6-overlay-noarch.tar.xz https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz \
    && wget -O /tmp/s6-overlay-x86_64.tar.xz https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-x86_64.tar.xz \
    && tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz \
    && tar -C / -Jxpf /tmp/s6-overlay-x86_64.tar.xz \
    && ln -s /command/* /bin/


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

COPY etc/cont-init.d /etc/cont-init.d
RUN find /etc/cont-init.d -exec chmod ug+x {} \;

COPY etc/services.d /etc/services.d
RUN find /etc/services.d -exec chmod ug+x {} \;


RUN \
    chmod +x /opt/dnsmap/proxy.py \
    && chmod +x /opt/dnsmap/*.sh

RUN \
    git clone https://bitbucket.org/anticensority/antizapret-pac-generator-light.git /opt/antizapret \
    && cd /opt/antizapret/config \
    && cat ./include-hosts-dist.txt >> ./include-hosts-custom.txt && > ./include-hosts-dist.txt \
    && cat ./include-ips-dist.txt >> ./include-ips-custom.txt && > ./include-ips-dist.txt \
    && cat ./exclude-ips-dist.txt >> ./exclude-ips-custom.txt && > ./exclude-ips-dist.txt \
    && cat ./exclude-hosts-dist.txt >> ./exclude-hosts-custom.txt && > ./exclude-hosts-dist.txt \
    && cat ./exclude-hosts-by-ips-dist.txt >> ./exclude-hosts-by-ips-custom.txt && > ./exclude-hosts-by-ips-dist.txt \
    && cd /opt/antizapret && mv config config_default

COPY opt/antizapret/process.sh /opt/antizapret/process.sh
COPY etc/sudoers.d/vpn /etc/sudoers.d/
RUN \
    useradd -u 2000 -M vpn \
    && usermod -a -G knot-resolver vpn \
    && chmod +x /opt/antizapret/process.sh \
    && mkdir /etc/antizapret \
    && ln -s /opt/antizapret/config \
    && chown -R vpn:vpn /opt/antizapret

COPY opt/wireguard /opt/wireguard

COPY etc/crontab /etc/crontab

ENTRYPOINT ["/init"]

