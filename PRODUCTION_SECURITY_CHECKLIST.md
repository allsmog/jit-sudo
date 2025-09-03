# JIT Sudo Production Security Checklist

## 🔐 Pre-Production Security Verification

### ⚡ Critical Security Requirements
- [ ] **NO HARDCODED SECRETS** - Verify all "dev-secret-key" strings removed
  ```bash
  grep -r "dev-secret-key\|mock\|hardcoded" . --include="*.rs" --include="*.c"
  # Expected: No results
  ```

- [ ] **Encryption at Rest** - All grants encrypted with AES-256-GCM
  ```bash
  strings /var/lib/jit-sudo/grants.db | grep -E "sub|jti|cmnd_patterns"
  # Expected: No readable grant data
  ```

- [ ] **Socket Permissions** - Verify proper root:sudo ownership
  ```bash
  ls -la /run/jit-sudo/jitd.sock
  # Expected: srw-rw---- 1 root sudo
  ```

- [ ] **No Mock Authentication** - Remove all local JWT generation
  ```bash
  grep -r "create_mock_token" . --include="*.rs"
  # Expected: No results
  ```

### 🛡️ Cryptographic Security
- [ ] **JWT Key Management**
  - [ ] RSA keys minimum 2048-bit or ECDSA P-256
  - [ ] Private keys stored with 0600 permissions
  - [ ] Public keys from trusted JWKS endpoint
  - [ ] Key rotation schedule defined (90 days recommended)

- [ ] **Signature Algorithms**
  - [ ] Using RS256, ES256, or stronger (no HS256)
  - [ ] Algorithm explicitly specified (no "none")
  - [ ] Signature validation enforced on every request

### 🔒 Access Control
- [ ] **Process Isolation**
  - [ ] Daemon runs as dedicated user (not root after initialization)
  - [ ] Systemd sandboxing enabled (ProtectSystem=strict)
  - [ ] SELinux/AppArmor policies configured

- [ ] **File Permissions**
  ```bash
  find /etc/jit-sudo -type f -exec ls -la {} \;
  # All config files: 0640 root:jitd
  find /var/lib/jit-sudo -type f -exec ls -la {} \;  
  # All data files: 0600 jitd:jitd
  ```

### 🚦 Input Validation
- [ ] **Command Pattern Security**
  - [ ] Regex patterns compiled and validated
  - [ ] Shell metacharacters escaped: `; & | > < $ \` { }`
  - [ ] Path traversal prevented (no ../ patterns)
  - [ ] Command allowlist/blocklist implemented

- [ ] **TTL Validation**
  - [ ] Maximum TTL enforced (recommended: 8 hours)
  - [ ] Minimum TTL enforced (recommended: 30 seconds)
  - [ ] Clock skew tolerance < 5 minutes

### 📊 Audit & Monitoring
- [ ] **Comprehensive Logging**
  - [ ] All grant requests logged with user, command, approval
  - [ ] All validation decisions logged with reason
  - [ ] Failed attempts logged with details
  - [ ] Log rotation configured

- [ ] **Security Events**
  - [ ] Alert on repeated failed attempts (>5 in 1 minute)
  - [ ] Alert on expired grant usage attempts
  - [ ] Alert on suspicious patterns (unusual commands)
  - [ ] Integration with SIEM configured

## 🔧 Operational Security

### System Hardening
```bash
# Kernel parameters
echo "kernel.yama.ptrace_scope=2" >> /etc/sysctl.d/99-jit-sudo.conf
echo "kernel.dmesg_restrict=1" >> /etc/sysctl.d/99-jit-sudo.conf
echo "kernel.kptr_restrict=2" >> /etc/sysctl.d/99-jit-sudo.conf

# File integrity monitoring
aide --init --config=/etc/aide/aide.conf
echo "/usr/libexec/jit-sudo/jitd f+p+u+g+s+m+c+md5+sha256" >> /etc/aide/aide.conf
```

### Network Security
- [ ] **IPC Security**
  - [ ] Unix sockets only (no network sockets)
  - [ ] Socket in protected directory (/run/jit-sudo)
  - [ ] No external network connections from daemon

- [ ] **Broker Communication** (if applicable)
  - [ ] TLS 1.3 minimum for HTTPS
  - [ ] Certificate pinning implemented
  - [ ] Mutual TLS authentication

### Dependency Security
```bash
# Rust dependencies audit
cargo audit --deny warnings

# Check for known CVEs
cargo deny check

# Verify dependency licenses
cargo deny check licenses

# C library verification
ldd /usr/libexec/jit-sudo/jit_approval.so
# Should only link to system libraries
```

## 🚨 Incident Response

### Emergency Procedures
- [ ] **Kill Switch** - Disable all grants immediately
  ```bash
  sudo systemctl stop jitd
  sudo rm -f /run/jit-sudo/jitd.sock
  echo "Plugin jit_approval /dev/null" > /etc/sudo.conf.emergency
  sudo mv /etc/sudo.conf.emergency /etc/sudo.conf
  ```

- [ ] **Audit Trail Preservation**
  ```bash
  sudo tar -czf /secure-backup/jit-sudo-audit-$(date +%Y%m%d).tar.gz \
    /var/log/jit-sudo/ /var/lib/jit-sudo/
  ```

### Recovery Procedures
- [ ] **Backup Strategy**
  - [ ] Daily encrypted backups of grant database
  - [ ] Configuration backups before changes
  - [ ] Key backup in secure offline storage

- [ ] **Restore Testing**
  - [ ] Monthly restore drill performed
  - [ ] Recovery time < 15 minutes verified
  - [ ] Data integrity verification process

## 📋 Compliance Requirements

### Regulatory Compliance
- [ ] **SOX Compliance**
  - [ ] Segregation of duties enforced
  - [ ] Approval workflows documented
  - [ ] Audit trails retained for 7 years

- [ ] **PCI DSS**
  - [ ] Access to cardholder systems restricted
  - [ ] Two-factor authentication required
  - [ ] Session recording for privileged access

- [ ] **HIPAA**
  - [ ] PHI access logging enabled
  - [ ] Encryption in transit and at rest
  - [ ] Access reviews quarterly

### Security Standards
- [ ] **NIST Cybersecurity Framework**
  - [ ] Identify: Asset inventory complete
  - [ ] Protect: Access controls implemented
  - [ ] Detect: Monitoring configured
  - [ ] Respond: Incident plan documented
  - [ ] Recover: Backup procedures tested

- [ ] **CIS Controls**
  - [ ] Control 4: Controlled use of admin privileges ✓
  - [ ] Control 6: Maintenance of audit logs ✓
  - [ ] Control 16: Account monitoring ✓

## 🔍 Security Testing

### Penetration Testing
```bash
# JWT Security Testing
python3 jwt_tool.py -t https://jit-broker.company.com -rc

# Fuzzing command patterns
AFL++ /usr/libexec/jit-sudo/jit_approval.so

# Race condition testing
stress-ng --race-sched 0 --timeout 60s
```

### Security Scanning
```bash
# Static analysis
semgrep --config=auto .
bandit -r . -ll

# Dynamic analysis
valgrind --leak-check=full /usr/libexec/jit-sudo/jitd

# Container scanning (if containerized)
trivy image jit-sudo:latest
```

## ✅ Final Production Readiness

### Go/No-Go Criteria
**MUST PASS ALL:**
- [ ] Zero critical vulnerabilities in security scan
- [ ] All hardcoded secrets removed
- [ ] Encryption implemented and tested
- [ ] Audit logging functional
- [ ] Incident response plan tested
- [ ] Security review completed by CISO
- [ ] Penetration test passed

### Sign-Off Requirements
- [ ] Security Team Lead: _________________ Date: _______
- [ ] Infrastructure Lead: ________________ Date: _______
- [ ] Compliance Officer: _________________ Date: _______
- [ ] CISO: ______________________________ Date: _______

## 📞 Security Contacts

**Security Incidents**: security@company.com / +1-555-SEC-RITY  
**On-Call Security**: PagerDuty #security-oncall  
**Vendor Support**: support@jit-sudo.com  

---

**Document Version**: 1.0  
**Last Updated**: September 3, 2025  
**Next Review**: December 3, 2025  
**Classification**: CONFIDENTIAL