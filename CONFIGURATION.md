# JIT Sudo Configuration Guide

## Overview

JIT Sudo uses a sophisticated configuration system that supports multiple file formats, environment variables, and command-line overrides with proper precedence handling. This replaces the previous environment-variable-only approach with a production-grade configuration management system.

## Configuration Precedence

Configuration is loaded in the following order (highest to lowest priority):

1. **Command-line arguments** (highest priority)
2. **Configuration files** (in order specified)
3. **Environment variables** (for backward compatibility)
4. **Compiled defaults** (lowest priority)

## Configuration File Formats

JIT Sudo supports multiple configuration formats:

- **TOML** (recommended): `/etc/jit-sudo/config.toml`
- **YAML**: `/etc/jit-sudo/config.yaml`  
- **JSON**: `/etc/jit-sudo/config.json`

## Configuration Structure

### Core Settings
```toml
[core]
socket_path = "/run/jit-sudo/jitd.sock"
storage_path = "/var/lib/jit-sudo"
log_level = "info"  # error, warn, info, debug, trace
max_connections = 100
request_timeout_secs = 30
```

### Security Configuration
```toml
[security]
encryption_enabled = true
key_storage = "tpm"  # tpm, file, kms, vault
key_directory = "/etc/jit-sudo/keys"
jwks_url = "https://auth.company.com/.well-known/jwks.json"
trusted_issuers = ["https://jit-broker.company.com"]
max_ttl_seconds = 14400  # 4 hours
require_tls = true
audit_integrity = true
```

### Approval Workflow
```toml
[approval]
mode = "risk-based"  # auto, manual, risk-based, disabled
require_justification = true
min_justification_length = 10
request_expiry_minutes = 30

[approval.risk_thresholds]
auto_approve = 2      # 0-2: Auto-approve
admin_approve = 6     # 3-6: Single admin  
multi_approve = 10    # 7-10: Multiple admins

[approval.auto_approve]
enabled = true
commands = ["ls", "cat", "grep", "ps", "df"]
max_ttl_seconds = 3600
business_hours_only = false
hours = "09:00-17:00"
days = "Mon-Fri"

[approval.never_approve]
commands = ["rm -rf", "dd", "shutdown"]
patterns = ["*password*", "*shadow*"]
```

### Risk Scoring
```toml
[risk_scoring]
[risk_scoring.command_weights]
rm = 5
systemctl = 3
iptables = 7
docker = 4

production_multiplier = 1.5
after_hours_bonus = 1
emergency_flag_bonus = 0
```

### Logging Configuration
```toml
[logging]
audit_path = "/var/log/jit-sudo/audit.log"
app_log_path = "/var/log/jit-sudo/app.log"
max_size_mb = 100
max_files = 10
format = "json"  # json, text, structured
syslog_enabled = true
syslog_facility = "local0"
```

### Notifications
```toml
[notifications]
slack_webhook = "https://hooks.slack.com/services/..."
admin_emails = ["security@company.com"]
user_notifications = true
cooldown_minutes = 5

[notifications.email]
smtp_host = "smtp.company.com"
smtp_port = 587
username = "jit-sudo@company.com"
use_tls = true
```

## Deployment Scenarios

### 1. Development Environment

**File**: `/etc/jit-sudo/config-dev.toml`

```toml
[approval]
mode = "auto"  # Auto-approve everything
require_justification = false

[approval.risk_thresholds]
auto_approve = 10  # Approve all commands

[security]
encryption_enabled = true
key_storage = "file"  # No TPM required
require_tls = false   # Allow HTTP for local dev

[logging]
log_level = "debug"
format = "text"  # Human-readable
```

### 2. Production Environment

**File**: `/etc/jit-sudo/config-prod.toml`

```toml
[approval]
mode = "risk-based"
require_justification = true
min_justification_length = 20

[approval.risk_thresholds]
auto_approve = 2
admin_approve = 6
multi_approve = 10

[security]
encryption_enabled = true
key_storage = "tpm"
require_tls = true
max_ttl_seconds = 3600  # 1 hour max
```

### 3. High Security Environment

**File**: `/etc/jit-sudo/config-high-security.toml`

```toml
[approval]
mode = "manual"  # ALL requests need approval
min_justification_length = 50

[approval.auto_approve]
enabled = false  # No auto-approval

[approval.risk_thresholds]
auto_approve = 0     # Disabled
admin_approve = 5    # Lower threshold
multi_approve = 7    # More multi-approvals

[security]
max_ttl_seconds = 3600  # 1 hour maximum
```

## Configuration Management CLI

### View Current Configuration
```bash
jitctl config show
jitctl config show --format yaml
jitctl config show --section approval
```

### Modify Configuration
```bash
# Set individual values
jitctl config set approval.mode risk-based
jitctl config set approval.risk_thresholds.auto_approve 3
jitctl config set security.encryption_enabled true

# Load from file
jitctl config import production-config.toml
jitctl config export > current-config.toml
```

### Validation
```bash
# Validate configuration files
jitctl config validate /etc/jit-sudo/config.toml
jitctl config validate --format yaml config.yaml

# Test configuration
jitctl config test --dry-run
```

### Environment-Specific Configs
```bash
# Load environment-specific overrides
jitctl config load --env production
jitctl config load --env development
jitctl config load --env high-security
```

## Environment Variable Compatibility

For backward compatibility, these environment variables are still supported:

```bash
# Legacy environment variables
export JIT_SOCKET_PATH=/run/jit-sudo/jitd.sock
export JIT_STORAGE_PATH=/var/lib/jit-sudo
export JIT_LOG_LEVEL=debug
export JIT_APPROVAL_MODE=risk-based
export JIT_AUTO_APPROVE_THRESHOLD=2
export JIT_JWKS_URL=https://auth.company.com/.well-known/jwks.json
```

**Note**: Configuration files take precedence over environment variables.

## Dynamic Configuration Reload

JIT Sudo supports hot-reloading of configuration without restart:

```bash
# Reload configuration
jitctl admin reload-config

# Watch for file changes (automatic reload)
jitd --watch-config

# Validate before reload
jitctl config validate && jitctl admin reload-config
```

## Configuration Security

### File Permissions
```bash
# Secure configuration files
sudo chown root:jitd /etc/jit-sudo/config.toml
sudo chmod 640 /etc/jit-sudo/config.toml

# Secure key directory
sudo chmod 700 /etc/jit-sudo/keys
sudo chmod 600 /etc/jit-sudo/keys/*
```

### Sensitive Values
Use environment variables or external secret management for sensitive values:

```toml
[notifications.email]
password = "$SMTP_PASSWORD"  # Resolved from environment

[security]
jwks_url = "$JWKS_ENDPOINT"  # Resolved at runtime
```

### Configuration Validation

The system validates configuration for:
- Valid approval modes
- Risk threshold consistency
- Path accessibility
- Security requirements
- Email/notification settings
- Command pattern validity

## Migration from Environment Variables

### Migration Script
```bash
#!/bin/bash
# migrate-config.sh

# Create configuration directory
sudo mkdir -p /etc/jit-sudo

# Generate initial config from current environment
jitctl config generate --from-env > /tmp/config.toml

# Validate generated config
jitctl config validate /tmp/config.toml

# Install configuration
sudo mv /tmp/config.toml /etc/jit-sudo/config.toml
sudo chown root:jitd /etc/jit-sudo/config.toml
sudo chmod 640 /etc/jit-sudo/config.toml

# Remove environment variables from systemd service
sudo systemctl edit jitd
# Remove Environment= lines

sudo systemctl daemon-reload
sudo systemctl restart jitd
```

## Advanced Configuration

### Per-Environment Configuration Structure
```
/etc/jit-sudo/
├── config.toml          # Base configuration
├── config.d/
│   ├── dev.toml         # Development overrides
│   ├── staging.toml     # Staging overrides  
│   └── prod.toml        # Production overrides
├── keys/
│   ├── private.pem
│   └── public.pem
└── policies/
    ├── auto-approve.yaml
    └── risk-scoring.yaml
```

### Configuration Templates

**Kubernetes ConfigMap**:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: jit-sudo-config
data:
  config.toml: |
    [core]
    socket_path = "/run/jit-sudo/jitd.sock"
    log_level = "info"
    
    [approval]
    mode = "risk-based"
    # ... rest of config
```

**Docker Compose**:
```yaml
version: '3.8'
services:
  jitd:
    image: jit-sudo:latest
    volumes:
      - ./config.toml:/etc/jit-sudo/config.toml:ro
      - ./keys:/etc/jit-sudo/keys:ro
    environment:
      - JIT_CONFIG_FILE=/etc/jit-sudo/config.toml
```

## Troubleshooting

### Common Issues

**Configuration not loading**:
```bash
# Check file permissions
ls -la /etc/jit-sudo/config.toml

# Validate syntax
jitctl config validate /etc/jit-sudo/config.toml

# Check logs
journalctl -u jitd | grep -i config
```

**Invalid configuration**:
```bash
# Show validation errors
jitctl config validate --verbose /etc/jit-sudo/config.toml

# Test configuration
jitd --config /etc/jit-sudo/config.toml --dry-run
```

**Environment variable conflicts**:
```bash
# Show effective configuration
jitctl config show --effective

# Show configuration sources
jitctl config show --sources
```

## Best Practices

1. **Version Control**: Store configuration files in version control
2. **Environment Separation**: Use separate configs for dev/staging/prod
3. **Validation**: Always validate before deployment
4. **Backup**: Backup configurations before changes
5. **Monitoring**: Monitor for configuration changes
6. **Documentation**: Document environment-specific settings
7. **Security**: Use proper file permissions and secret management

## Migration Checklist

- [ ] Backup existing environment variable configuration
- [ ] Generate configuration file from current settings
- [ ] Validate generated configuration
- [ ] Test in development environment
- [ ] Update deployment scripts/containers
- [ ] Remove environment variables from service files
- [ ] Deploy to production with monitoring
- [ ] Verify functionality post-migration