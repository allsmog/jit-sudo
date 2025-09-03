# JIT Sudo Makefile

.PHONY: all clean install test check

# Build configuration
CARGO_TARGET_DIR ?= target
INSTALL_PREFIX ?= /usr/local
SUDO_PLUGIN_DIR ?= /usr/libexec/jit-sudo

# Component directories
LIBJIT_DIR = libjit-sudo
JITD_DIR = jitd  
PLUGIN_DIR = jit-approval-plugin
JITCTL_DIR = jitctl

all: libjit jitd plugin jitctl

# Build Rust components
libjit:
	cd $(LIBJIT_DIR) && cargo build --release

jitd: libjit
	cd $(JITD_DIR) && cargo build --release

jitctl: libjit
	cd $(JITCTL_DIR) && cargo build --release

# Build C plugin
plugin: libjit
	cd $(PLUGIN_DIR) && make

# Install system components
install: all
	install -d $(DESTDIR)$(SUDO_PLUGIN_DIR)
	install -m 755 $(PLUGIN_DIR)/jit_approval.so $(DESTDIR)$(SUDO_PLUGIN_DIR)/
	install -m 755 $(CARGO_TARGET_DIR)/release/jitd $(DESTDIR)$(INSTALL_PREFIX)/sbin/
	install -m 755 $(CARGO_TARGET_DIR)/release/jitctl $(DESTDIR)$(INSTALL_PREFIX)/bin/
	install -d $(DESTDIR)/etc/systemd/system
	install -m 644 jitd/jitd.service $(DESTDIR)/etc/systemd/system/

# Development and testing
test:
	cd $(LIBJIT_DIR) && cargo test
	cd $(JITD_DIR) && cargo test
	cd $(JITCTL_DIR) && cargo test
	cd $(PLUGIN_DIR) && make test

check:
	cd $(LIBJIT_DIR) && cargo clippy
	cd $(JITD_DIR) && cargo clippy  
	cd $(JITCTL_DIR) && cargo clippy

clean:
	cd $(LIBJIT_DIR) && cargo clean
	cd $(JITD_DIR) && cargo clean
	cd $(JITCTL_DIR) && cargo clean
	cd $(PLUGIN_DIR) && make clean
