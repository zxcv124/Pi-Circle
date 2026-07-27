FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.title="Pi-Circle"
LABEL org.opencontainers.image.description="Pi-Circle family network command dashboard and appliance agent"
LABEL org.opencontainers.image.source="https://github.com/zxcv124/Pi-Circle"
LABEL org.opencontainers.image.licenses="Pi-Circle Attribution Non-Enterprise License"

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PI_CIRCLE_CONFIG=/etc/pi-circle/config.toml
ENV PI_CIRCLE_WEB_DIR=/opt/pi-circle/source/web

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    conntrack \
    curl \
    dnsutils \
    dsniff \
    iproute2 \
    nftables \
    procps \
    sqlite3 \
    sudo \
    tini \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/pi-circle/source

COPY pyproject.toml README.md LICENSE NOTICE AUTHORS ./
COPY src ./src
COPY web ./web
COPY packaging ./packaging
COPY scripts ./scripts
COPY docker/entrypoint.sh /usr/local/bin/pi-circle-docker-entrypoint
COPY docker/helpers/pi-circle-set-arp-assisted-targets /usr/local/sbin/pi-circle-set-arp-assisted-targets
COPY docker/helpers/pi-circle-set-network-flags /usr/local/sbin/pi-circle-set-network-flags
COPY docker/helpers/pi-circle-emergency-dns-only /usr/local/sbin/pi-circle-emergency-dns-only

RUN python -m pip install --no-cache-dir --upgrade pip wheel \
  && python -m pip install --no-cache-dir . \
  && chmod 0755 /usr/local/bin/pi-circle-docker-entrypoint \
    /usr/local/sbin/pi-circle-set-arp-assisted-targets \
    /usr/local/sbin/pi-circle-set-network-flags \
    /usr/local/sbin/pi-circle-emergency-dns-only \
  && groupadd --system pi-circle \
  && useradd --system --home-dir /var/lib/pi-circle --shell /usr/sbin/nologin --gid pi-circle pi-circle \
  && install -d -o root -g pi-circle -m 0750 /etc/pi-circle \
  && install -d -o root -g pi-circle -m 2770 /var/lib/pi-circle /var/log/pi-circle \
  && printf '%s\n' \
    'Defaults:pi-circle !requiretty' \
    'pi-circle ALL=(root) NOPASSWD: /usr/local/sbin/pi-circle-set-arp-assisted-targets *' \
    'pi-circle ALL=(root) NOPASSWD: /usr/local/sbin/pi-circle-set-network-flags *' \
    'pi-circle ALL=(root) NOPASSWD: /usr/local/sbin/pi-circle-emergency-dns-only' \
    > /etc/sudoers.d/pi-circle-dashboard \
  && chmod 0440 /etc/sudoers.d/pi-circle-dashboard \
  && visudo -cf /etc/sudoers.d/pi-circle-dashboard >/dev/null

VOLUME ["/etc/pi-circle", "/var/lib/pi-circle", "/var/log/pi-circle", "/etc/pihole"]

EXPOSE 8088

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:8088/api/health >/dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/pi-circle-docker-entrypoint"]
