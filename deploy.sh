#!/usr/bin/env bash
# R-NADS deployment package builder
set -e

echo "=== R-NADS: Deployment Packaging ==="

# 1. Install compile-time and runtime requirements
echo "[1/4] Installing system dependencies..."
if command -v apt-get &> /dev/null; then
    sudo apt-get update -y && sudo apt-get install -y libsqlite3-dev pkg-config libpcap-dev
else
    echo "Notice: apt-get not found. Make sure libpcap, sqlite3 development libraries, and pkg-config are installed."
fi

# 2. Compile Release Binary with native CPU optimizations (SIMD/AVX2)
echo "[2/4] Compiling release binary..."
CARGO_TARGET_DIR=/tmp/cargo-target cargo build --release

# 3. Create the distribution folder
echo "[3/4] Packaging binary and configuration..."
mkdir -p dist
cp /tmp/cargo-target/release/r-nads dist/
cp config.toml dist/

# 4. Set network capture capabilities on the binary
echo "[4/4] Setting raw packet capture capabilities..."
if command -v setcap &> /dev/null; then
    sudo setcap cap_net_raw,cap_net_admin=eip dist/r-nads
    echo "Capabilities set successfully. r-nads can be run by non-root users."
else
    echo "Warning: setcap not found. You will need to run r-nads using sudo/root."
fi

# Create a systemd service template inside the dist folder
cat <<EOF > dist/r-nads.service
[Unit]
Description=R-NADS Network Anomaly Detection System Daemon
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/r-nads
ExecStart=/opt/r-nads/r-nads
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

echo "============================================="
echo "=== Deployment package ready in './dist' ==="
echo "============================================="
echo "This directory is self-contained and ready to copy to your server."
echo ""
echo "To run the intrusion detection system (classify mode using pretrained weights):"
echo "  cd dist && ./r-nads"
echo ""
echo "To retrain the model baseline on your server interface (e.g. eth0):"
echo "  cd dist && ./r-nads --mode train"
echo ""
echo "To install as a system service:"
echo "  sudo cp -r dist /opt/r-nads"
echo "  sudo cp /opt/r-nads/r-nads.service /etc/systemd/system/"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable --now r-nads"
EOF
