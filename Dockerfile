# Multi-stage build for tproxy-server
FROM golang:1.24-alpine AS builder

WORKDIR /src

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build static binary
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /usr/local/bin/tproxy-server \
    ./cmd/tproxy-server

# Runtime image
FROM alpine:3.21

# Create dedicated unprivileged user and group
RUN addgroup -g 10001 -S tproxy && \
    adduser -u 10001 -S -G tproxy -h /etc/tproxy-server -s /sbin/nologin tproxy

# Create directory structure
RUN mkdir -p /etc/tproxy-server /srv/tproxy-site /run/telemt /tmp/tproxy-runtime && \
    chown -R tproxy:tproxy /etc/tproxy-server /srv/tproxy-site /run/telemt /tmp/tproxy-runtime

# Copy executable and entrypoint script
COPY --from=builder /usr/local/bin/tproxy-server /usr/local/bin/tproxy-server
COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh /usr/local/bin/tproxy-server

# Copy default example configuration and profiles
COPY config.example.json /etc/tproxy-server/config.example.json
COPY profiles.example.json /etc/tproxy-server/profiles.example.json

WORKDIR /etc/tproxy-server

EXPOSE 8080 8081

HEALTHCHECK --interval=20s --timeout=5s --start-period=5s --retries=3 \
    CMD wget -q -O - http://127.0.0.1:8081/healthz > /dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["tproxy-server", "-config", "/etc/tproxy-server/config.json"]
