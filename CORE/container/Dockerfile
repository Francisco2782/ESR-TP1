FROM ghcr.io/eivarin/coreemu:9.2.1

RUN mkdir -p /build

# netcat is used in the core-gui script to check if the container is ready.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        netcat-openbsd ca-certificates curl xz-utils gnupg unzip && \
    apt-get autoremove -y

# ---------------------------------------------------------------------------
# Packages from packages.txt
# ---------------------------------------------------------------------------
# Strip comments/blanks, then install. If the batch install fails because a
# package name is not in the repos, fall back to per-package install and just
# warn — so a stale name like `ngtcp2-client` never breaks the whole build.
COPY packages.txt /build/packages.txt
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    set -eux; \
    apt-get update; \
    sed -e 's/#.*//' -e '/^[[:space:]]*$/d' /build/packages.txt > /tmp/pkgs.txt; \
    if ! xargs -a /tmp/pkgs.txt -r apt-get install -y --no-install-recommends; then \
        echo "WARN: batch install failed, retrying package by package" >&2; \
        : > /tmp/missing.txt; \
        while IFS= read -r pkg; do \
            apt-get install -y --no-install-recommends "$pkg" \
                || echo "$pkg" >> /tmp/missing.txt; \
        done < /tmp/pkgs.txt; \
        if [ -s /tmp/missing.txt ]; then \
            echo "WARN: could not install:" >&2; \
            cat /tmp/missing.txt >&2; \
        fi; \
    fi; \
    apt-get autoremove -y

# ---------------------------------------------------------------------------
# Caddy (not in default Ubuntu repos)
# ---------------------------------------------------------------------------
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        debian-keyring debian-archive-keyring apt-transport-https curl gnupg && \
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
        | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg && \
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
        | tee /etc/apt/sources.list.d/caddy-stable.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends caddy && \
    apt-get autoremove -y

# ---------------------------------------------------------------------------
# Fully static HTTP/2 + HTTP/3 curl (musl build)
# ---------------------------------------------------------------------------
# The ESR TP1 lab ships tools/curl-http3/bin/curl.bin linked against glibc
# >= 2.38 (via a bundled OpenSSL 3.4 libcrypto.so.3). This image is Ubuntu
# 22.04 (glibc 2.35), so that binary cannot run. The musl static-curl binary
# has no dynamic dependencies at all and works everywhere.
ARG CURL_VER=8.11.1
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) curl_arch=x86_64 ;; \
      arm64) curl_arch=aarch64 ;; \
      *) echo "unsupported arch: $arch"; exit 1 ;; \
    esac; \
    url="https://github.com/stunnel/static-curl/releases/download/${CURL_VER}/curl-linux-${curl_arch}-musl-${CURL_VER}.tar.xz"; \
    mkdir -p /opt/http3-curl; \
    curl -fsSL "$url" -o /tmp/curl.tar.xz; \
    tar -xJf /tmp/curl.tar.xz -C /opt/http3-curl; \
    chmod 0755 /opt/http3-curl/curl; \
    rm -f /tmp/curl.tar.xz; \
    ln -sf /opt/http3-curl/curl /usr/local/bin/curl; \
    hash -r; \
    /usr/local/bin/curl -V

# ---------------------------------------------------------------------------
# Runtime helpers: auto-init (unzip + fix-curl) + manual fix command
# ---------------------------------------------------------------------------
# The lab zip lives in the shared volume and is only available at runtime,
# so we cannot unzip it during build. Instead, an init script under
# /etc/profile.d runs on every interactive shell (also sourced from
# /etc/bash.bashrc for non-login shells) and:
#   1. mkdir -p ~/esr && unzip /volume/ESR-TP1-26-27-resources.zip -d ~/esr
#   2. replace the lab's curl.bin with /opt/http3-curl/curl
# Both steps are idempotent and use sentinels so they are cheap.
COPY esr-tp1-init.sh /etc/profile.d/00-esr-tp1-init.sh
RUN chmod 0644 /etc/profile.d/00-esr-tp1-init.sh && \
    printf '\n# ESR TP1: run container init on non-login interactive shells too\n[ -r /etc/profile.d/00-esr-tp1-init.sh ] && . /etc/profile.d/00-esr-tp1-init.sh\n' \
        >> /etc/bash.bashrc

COPY fix-lab-curl.sh /usr/local/bin/fix-lab-curl
RUN chmod 0755 /usr/local/bin/fix-lab-curl

# ---------------------------------------------------------------------------
# Firefox (kept from your original Dockerfile)
# ---------------------------------------------------------------------------
COPY install-firefox.sh /build/install-firefox.sh
RUN sh /build/install-firefox.sh