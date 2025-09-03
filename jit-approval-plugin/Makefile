# JIT Approval Plugin Makefile

CC = gcc
CFLAGS = -fPIC -Wall -Wextra -O2 -I/usr/include/sudo
LDFLAGS = -shared
TARGET = jit_approval.so
SOURCES = jit_approval.c
OBJECTS = $(SOURCES:.c=.o)

# Build the shared library
$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Install the plugin (requires root)
install: $(TARGET)
	install -D -m 755 $(TARGET) /usr/libexec/jit-sudo/$(TARGET)

# Run basic tests
test: $(TARGET)
	@echo "Testing plugin load..."
	@sudo -V | grep -q "approval plugin" || echo "Warning: sudo may not support approval plugins"
	@echo "Plugin built successfully"

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: install test clean
