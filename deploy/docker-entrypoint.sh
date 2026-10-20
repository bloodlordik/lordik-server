#!/bin/sh
set -eu

RUNTIME_DIR="/tmp/tproxy-runtime"
CONFIG_DIR="/etc/tproxy-server"
SITE_DIR="/srv/tproxy-site"
SOCKET_DIR="/run/telemt"

mkdir -p "$CONFIG_DIR" "$SITE_DIR" "$SOCKET_DIR" "$RUNTIME_DIR"

# 1. Fallback config.json if missing
if [ ! -f "$CONFIG_DIR/config.json" ]; then
    if [ -f "$CONFIG_DIR/config.example.json" ]; then
        cp "$CONFIG_DIR/config.example.json" "$CONFIG_DIR/config.json"
    else
        cat << 'EOF' > "$CONFIG_DIR/config.json"
{
  "public_hostname": "proxy.example.com",
  "base_path": "",
  "listen": "127.0.0.1:8080",
  "admin_listen": "127.0.0.1:8081",
  "public_dir": "/srv/tproxy-site",
  "backend_type": "telemt",
  "backend_proxy_protocol": "v2",
  "token_key_file": "/etc/tproxy-server/token.key",
  "static_routes": "exact",
  "profiles_file": "/etc/tproxy-server/profiles.json",
  "enable_pprof": false
}
EOF
    fi
    chown tproxy:tproxy "$CONFIG_DIR/config.json" 2>/dev/null || true
fi

# 2. Fallback profiles.json if missing
if [ ! -f "$CONFIG_DIR/profiles.json" ]; then
    if [ -f "$CONFIG_DIR/profiles.example.json" ]; then
        cp "$CONFIG_DIR/profiles.example.json" "$CONFIG_DIR/profiles.json"
    else
        cat << 'EOF' > "$CONFIG_DIR/profiles.json"
{
  "profiles": [
    {
      "name": "default",
      "secret": "000102030405060708090a0b0c0d0e0f",
      "backend": "127.0.0.1:8443",
      "backend_type": "telemt",
      "backend_proxy_protocol": "v2",
      "carrier_mode": "https-lanes"
    }
  ]
}
EOF
    fi
    chmod 0600 "$CONFIG_DIR/profiles.json" 2>/dev/null || true
    chown tproxy:tproxy "$CONFIG_DIR/profiles.json" 2>/dev/null || true
fi

# 3. Ensure token.key (exactly 32 random bytes, strictly private 0400)
TOKEN_KEY="$CONFIG_DIR/token.key"
if [ ! -f "$TOKEN_KEY" ] || [ "$(wc -c < "$TOKEN_KEY" 2>/dev/null || echo 0)" -ne 32 ]; then
    head -c 32 /dev/urandom > "$TOKEN_KEY"
fi
chmod 0400 "$TOKEN_KEY" 2>/dev/null || true
chown tproxy:tproxy "$TOKEN_KEY" 2>/dev/null || true

# 4. Check profiles.json permissions (preventing permission error on read-only host mounts)
PROFILES_FILE="$CONFIG_DIR/profiles.json"
ACTUAL_PROFILES="$PROFILES_FILE"
if [ -f "$PROFILES_FILE" ]; then
    if ! chmod 0600 "$PROFILES_FILE" 2>/dev/null; then
        # In case the file is on a read-only mount with 0644 permissions,
        # copy it to runtime directory with strict 0600 permissions.
        cp "$PROFILES_FILE" "$RUNTIME_DIR/profiles.json"
        chmod 0600 "$RUNTIME_DIR/profiles.json"
        chown tproxy:tproxy "$RUNTIME_DIR/profiles.json" 2>/dev/null || true
        ACTUAL_PROFILES="$RUNTIME_DIR/profiles.json"
    else
        chown tproxy:tproxy "$PROFILES_FILE" 2>/dev/null || true
    fi
fi

# 5. Provide minimal public site index.html if public_dir is empty
if [ -d "$SITE_DIR" ] && [ ! -f "$SITE_DIR/index.html" ]; then
    cat << 'EOF' > "$SITE_DIR/index.html"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>Welcome</title>
    <style>body{font-family:system-ui,-apple-system,sans-serif;margin:4rem auto;max-width:600px;line-height:1.6;color:#333;padding:0 1rem;}</style>
</head>
<body>
    <h1>Welcome</h1>
    <p>This web server is operating normally.</p>
</body>
</html>
EOF
    chown tproxy:tproxy "$SITE_DIR/index.html" 2>/dev/null || true
fi

# 6. Ensure socket directory is accessible across containers
chmod 777 "$SOCKET_DIR" 2>/dev/null || true
chown -R tproxy:tproxy "$SITE_DIR" "$SOCKET_DIR" "$RUNTIME_DIR" 2>/dev/null || true

# 7. If profiles file was copied to runtime dir, inject -profiles-file flag if not explicitly set
if [ "${1:-}" = "tproxy-server" ] && [ "$ACTUAL_PROFILES" != "$PROFILES_FILE" ]; then
    has_profiles_arg=0
    for arg in "$@"; do
        case "$arg" in
            -profiles-file*) has_profiles_arg=1 ;;
        esac
    done
    if [ "$has_profiles_arg" -eq 0 ]; then
        set -- "$@" -profiles-file "$ACTUAL_PROFILES"
    fi
fi

# 8. Drop privileges to tproxy user if running as root
if [ "$(id -u)" = "0" ]; then
    exec su -s /bin/sh tproxy -c 'exec "$@"' -- "$@"
fi

exec "$@"
