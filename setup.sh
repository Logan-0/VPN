#!/bin/bash
# Setup script for RustVPN
# Automatically detects and sets up required capabilities for running without sudo

set -e

BINARY_PATH="./target/release/rust-vpn"

echo "Setting up RustVPN..."

# Check if binary exists
if [ ! -f "$BINARY_PATH" ]; then
    echo "Error: Binary not found at $BINARY_PATH"
    echo "Please run 'cargo build --release' first"
    exit 1
fi

# Check if CAP_NET_ADMIN is already set
if getcap "$BINARY_PATH" | grep -q "cap_net_admin"; then
    echo "CAP_NET_ADMIN capability already set on $BINARY_PATH"
else
    echo "Setting CAP_NET_ADMIN capability on $BINARY_PATH..."
    sudo setcap cap_net_admin+ep "$BINARY_PATH"
    echo "Capability set successfully"
fi

# Verify the capability was set
if getcap "$BINARY_PATH" | grep -q "cap_net_admin"; then
    echo "Setup complete! You can now run:"
    echo "  $BINARY_PATH"
else
    echo "Error: Failed to set capability"
    exit 1
fi
