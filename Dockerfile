# ═══════════════════════════════════════════════════════════════════════════
# TorVPN — Dockerfile (Linux / amd64)
#
# Build:  docker build -t torvpn .
# Run:    docker run --rm --cap-add=NET_ADMIN --device /dev/net/tun \
#                    -p 9050:9050 torvpn
#
# The container needs:
#   --cap-add=NET_ADMIN  — to create TUN interface and modify routes
#   --device /dev/net/tun — kernel TUN device
# ═══════════════════════════════════════════════════════════════════════════

# ── Stage 1: Build ──────────────────────────────────────────────────────
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Copy dependency files first (better layer caching)
COPY go.mod go.sum* ./
RUN go mod download

# Copy source
COPY . .

# Build a statically-linked binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w -extldflags '-static'" \
    -trimpath \
    -o /out/torvpn ./cmd/torvpn/

# ── Stage 2: Runtime ────────────────────────────────────────────────────
FROM debian:bookworm-slim

# Install Tor and iproute2 (for `ip` command)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tor \
        iproute2 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create a non-root user for Tor itself (TorVPN binary runs as root for TUN)
RUN useradd -r -s /bin/false -m -d /var/lib/tor tor

# Copy the compiled binary
COPY --from=builder /out/torvpn /usr/local/bin/torvpn
RUN chmod 755 /usr/local/bin/torvpn

# Copy default torrc
COPY configs/torrc /etc/torvpn/torrc
RUN chmod 600 /etc/torvpn/torrc

# Create Tor data directory
RUN mkdir -p /var/lib/tor-data && chown root:root /var/lib/tor-data && chmod 700 /var/lib/tor-data

# Update torrc data directory for Docker
RUN sed -i 's|DataDirectory.*|DataDirectory /var/lib/tor-data|' /etc/torvpn/torrc

# Expose SOCKS5 port (useful if running TorVPN as a proxy without TUN)
EXPOSE 9050

# Health check: verify Tor's SOCKS5 port is up
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD nc -z 127.0.0.1 9050 || exit 1

# Entry point
ENTRYPOINT ["/usr/local/bin/torvpn"]
CMD ["-torrc", "/etc/torvpn/torrc", \
     "-tun", "torvpn0", \
     "-ip", "10.0.0.1/24", \
     "-dns", "127.0.0.1:5300", \
     "-socks-port", "9050", \
     "-control-port", "9051", \
     "-control-pass", "torvpnpass", \
     "-rotate", "600", \
     "-verbose"]
