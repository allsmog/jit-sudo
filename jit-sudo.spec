%define _topdir %{getenv:HOME}/rpmbuild
%define name jit-sudo
%define version 1.0.0
%define release 1

Name:           %{name}
Version:        %{version}
Release:        %{release}%{?dist}
Summary:        Just-In-Time sudo access with approval workflows

License:        MIT
URL:            https://github.com/allsmog/jit-sudo
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  rust >= 1.70
BuildRequires:  cargo
BuildRequires:  gcc
BuildRequires:  openssl-devel
BuildRequires:  systemd-rpm-macros

Requires:       sudo >= 1.9.0
Requires:       openssl-libs
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
JIT Sudo provides time-limited, auditable sudo access through intelligent
approval workflows. It replaces permanent sudo privileges with temporary,
cryptographically-verified grants that automatically expire.

Key features:
* Time-limited sudo access (TTL-based expiration)
* Smart risk-based approval system
* Auto-approval for safe commands, admin approval for sensitive operations
* Complete audit trails for compliance (SOX/PCI/HIPAA)
* Enterprise integration (Slack, email, OIDC/SAML)
* Encrypted storage with AES-256-GCM
* Production-ready security hardening

%prep
%setup -q

%build
# Build Rust components
cargo build --release --workspace

# Build C plugin
cd jit-approval-plugin
gcc -shared -fPIC -o jit_approval.so jit_approval.c -I/usr/include/sudo

%install
rm -rf $RPM_BUILD_ROOT

# Create directory structure
mkdir -p $RPM_BUILD_ROOT/usr/bin
mkdir -p $RPM_BUILD_ROOT/usr/sbin
mkdir -p $RPM_BUILD_ROOT/usr/lib/jit-sudo
mkdir -p $RPM_BUILD_ROOT/etc/jit-sudo/keys
mkdir -p $RPM_BUILD_ROOT/var/lib/jit-sudo
mkdir -p $RPM_BUILD_ROOT/var/log/jit-sudo
mkdir -p $RPM_BUILD_ROOT/usr/lib/systemd/system

# Install binaries
install -m 755 target/release/jitctl $RPM_BUILD_ROOT/usr/bin/
install -m 755 target/release/jitd $RPM_BUILD_ROOT/usr/sbin/
install -m 755 jit-approval-plugin/jit_approval.so $RPM_BUILD_ROOT/usr/lib/jit-sudo/

# Install systemd service
install -m 644 jitd/jitd.service $RPM_BUILD_ROOT/usr/lib/systemd/system/

# Install default configuration
cat > $RPM_BUILD_ROOT/etc/jit-sudo/config.toml << 'EOF'
# JIT Sudo Default Configuration
# Edit this file to customize your deployment

[core]
socket_path = "/run/jit-sudo/jitd.sock"
storage_path = "/var/lib/jit-sudo"
log_level = "info"

[security]
encryption_enabled = true
key_storage = "file"
key_directory = "/etc/jit-sudo/keys"

[approval]
mode = "risk-based"
require_justification = true
min_justification_length = 10

[approval.risk_thresholds]
auto_approve = 2
admin_approve = 6
multi_approve = 10

[approval.auto_approve]
enabled = true
max_ttl_seconds = 3600
commands = [
    "ls", "cat", "grep", "head", "tail", "find",
    "ps", "df", "free", "whoami", "id", "date"
]

[logging]
audit_path = "/var/log/jit-sudo/audit.log"
app_log_path = "/var/log/jit-sudo/app.log"
format = "json"

[notifications]
admin_emails = ["admin@localhost"]
user_notifications = true
EOF

%pre
# Create jitd user and group
getent group jitd >/dev/null || groupadd -r jitd
getent passwd jitd >/dev/null || \
    useradd -r -g jitd -d /var/lib/jit-sudo -s /sbin/nologin \
    -c "JIT Sudo daemon" jitd

%post
# Set proper ownership and permissions
chown jitd:jitd /var/lib/jit-sudo
chown jitd:jitd /var/log/jit-sudo
chmod 750 /var/lib/jit-sudo
chmod 750 /var/log/jit-sudo

# Secure configuration directory
chown root:jitd /etc/jit-sudo
chown root:jitd /etc/jit-sudo/keys
chown root:jitd /etc/jit-sudo/config.toml
chmod 750 /etc/jit-sudo
chmod 750 /etc/jit-sudo/keys
chmod 640 /etc/jit-sudo/config.toml

# Generate cryptographic keys
if [ ! -f /etc/jit-sudo/keys/private.pem ]; then
    openssl ecparam -genkey -name prime256v1 -out /etc/jit-sudo/keys/private.pem
    openssl ec -in /etc/jit-sudo/keys/private.pem -pubout -out /etc/jit-sudo/keys/public.pem
    chown root:jitd /etc/jit-sudo/keys/*.pem
    chmod 640 /etc/jit-sudo/keys/private.pem
    chmod 644 /etc/jit-sudo/keys/public.pem
fi

# Configure sudo plugin
SUDO_CONF="/etc/sudo.conf"
JIT_PLUGIN_LINE="Plugin jit_approval /usr/lib/jit-sudo/jit_approval.so"

if [ -f "$SUDO_CONF" ] && ! grep -q "jit_approval" "$SUDO_CONF"; then
    echo "$JIT_PLUGIN_LINE" >> "$SUDO_CONF"
elif [ ! -f "$SUDO_CONF" ]; then
    echo "$JIT_PLUGIN_LINE" > "$SUDO_CONF"
fi

# Enable and start systemd service
%systemd_post jitd.service

echo ""
echo "🎉 JIT Sudo installation complete!"
echo ""
echo "Quick start:"
echo "  jitctl request --cmd \"ls /var/log\" --ttl 5m --justification \"Check logs\""
echo "  jitctl status"
echo ""
echo "Configuration: /etc/jit-sudo/config.toml"
echo "Documentation: https://github.com/allsmog/jit-sudo/blob/main/README.md"
echo ""

%preun
%systemd_preun jitd.service

# Remove sudo plugin configuration (only on uninstall)
if [ $1 -eq 0 ]; then
    if [ -f /etc/sudo.conf ]; then
        sed -i '/jit_approval/d' /etc/sudo.conf
    fi
fi

%postun
%systemd_postun_with_restart jitd.service

# Remove user and directories on complete removal
if [ $1 -eq 0 ]; then
    userdel jitd 2>/dev/null || true
    groupdel jitd 2>/dev/null || true
    rm -rf /var/lib/jit-sudo
    rm -rf /var/log/jit-sudo
    rm -rf /run/jit-sudo
fi

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc README.md CONFIGURATION.md SECURITY_AUDIT.md
%license LICENSE

# Binaries
/usr/bin/jitctl
/usr/sbin/jitd
/usr/lib/jit-sudo/jit_approval.so

# Configuration
%config(noreplace) /etc/jit-sudo/config.toml
%dir %attr(750,root,jitd) /etc/jit-sudo
%dir %attr(750,root,jitd) /etc/jit-sudo/keys

# Data directories
%dir %attr(750,jitd,jitd) /var/lib/jit-sudo
%dir %attr(750,jitd,jitd) /var/log/jit-sudo

# Systemd service
/usr/lib/systemd/system/jitd.service

%changelog
* Wed Sep 04 2025 JIT Sudo Team <support@jit-sudo.io> - 1.0.0-1
- Initial RPM release
- Complete JIT sudo implementation with approval workflows
- Security hardening and audit trails
- Enterprise integration capabilities