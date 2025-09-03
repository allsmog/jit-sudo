# JIT Sudo Installation Guide

## Quick Start

```bash
# Clone repository
git clone https://github.com/allsmog/jit-sudo.git
cd jit-sudo

# Build all components
make all

# Install system components (requires root)
sudo make install

# Start daemon
sudo systemctl enable jitd
sudo systemctl start jitd

# Configure sudo
echo "Plugin jit_approval /usr/libexec/jit-sudo/jit_approval.so" | sudo tee -a /etc/sudo.conf
```

## Manual Installation

### 1. Build Components

```bash
# Build Rust libraries and binaries
cd libjit-sudo && cargo build --release && cd ..
cd jitd && cargo build --release && cd ..
cd jitctl && cargo build --release && cd ..

# Build C plugin
cd jit-approval-plugin && make && cd ..
```

### 2. Install Files

```bash
# Install binaries
sudo install -D -m 755 target/release/jitd /usr/local/sbin/
sudo install -D -m 755 target/release/jitctl /usr/local/bin/

# Install plugin
sudo install -D -m 755 jit-approval-plugin/jit_approval.so /usr/libexec/jit-sudo/

# Install systemd service
sudo install -D -m 644 jitd/jitd.service /etc/systemd/system/
sudo systemctl daemon-reload
```

### 3. Configure Sudo

Edit `/etc/sudo.conf`:

```
# Keep existing policies
Plugin sudoers_policy sudoers.so
Plugin sudoers_io     sudoers.so

# Add JIT approval
Plugin jit_approval /usr/libexec/jit-sudo/jit_approval.so
```

### 4. Start Services

```bash
# Enable and start daemon
sudo systemctl enable jitd
sudo systemctl start jitd

# Check status
sudo systemctl status jitd
```

## Usage

```bash
# Request temporary sudo access
jitctl request --cmd "systemctl restart nginx" --ttl 15m

# Check current grants
jitctl status

# Run command with JIT wrapper
jitctl run systemctl restart nginx

# Or just use sudo directly (after requesting grant)
sudo systemctl restart nginx
```

## Troubleshooting

```bash
# Check daemon logs
sudo journalctl -u jitd -f

# Check plugin debug logs
sudo tail -f /tmp/jit_approval.log

# Verify plugin loading
sudo -V | grep -i plugin

# Test socket communication
sudo -u azureuser ls -la /run/jit-sudo/
```

## Development Setup

```bash
# Install dependencies
sudo apt update
sudo apt install -y build-essential curl git pkg-config libssl-dev

# Install Rust
curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Build in debug mode
make CARGO_PROFILE=debug
```
