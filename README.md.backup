# JIT Sudo Access System

A Just-In-Time (JIT) sudo access library and its on-host + control-plane components.

## Architecture

- **libjit-sudo/**: Rust core library for token verification and policy evaluation
- **jitd/**: Root daemon for grant caching and IPC
- **jit-approval-plugin/**: C sudo approval plugin (jit_approval.so)
- **jitctl/**: CLI tool for requesting and managing grants
- **docs/**: Documentation and design specs
- **tests/**: Integration and unit tests

## Components Status

| Component | Status | Description |
|-----------|---------|-------------|
| libjit-sudo | 🚧 Planning | Core Rust library |
| jitd | 🚧 Planning | Root daemon |
| jit-approval-plugin | 🚧 Planning | Sudo plugin |
| jitctl | 🚧 Planning | CLI tool |

## Development Environment

- **OS**: Ubuntu 22.04 LTS
- **Sudo Version**: 1.9.9 (supports approval plugins)
- **Rust**: 1.89.0
- **Build Tools**: GCC 11, make, pkg-config

## Quick Start

```bash
# Build all components
make all

# Install on local system (requires root)
sudo make install

# Run tests
make test
```

## References

- [Sudo 1.9 Plugin API](https://www.sudo.ws/docs/man/1.9.9/sudo_plugin.man.html)
- [JIT Design Document](docs/design.md)
