# MCP Jail - Build targets
# https://mcpjail.com

.PHONY: all build release test test-unit test-security test-integration clean install help

# Default target
all: build

# Build debug version
build:
	cargo build

# Build release version
release:
	cargo build --release

# Run all tests (unit + security integration)
test: test-unit test-security

# Run Rust unit tests
test-unit:
	cargo test

# Run security integration tests
# These prove mcpjail blocks real vulnerabilities found in 501 MCP servers
test-security: release
	@echo "Running security integration tests..."
	@echo "Testing against vulnerabilities from MCP security audit:"
	@echo "  - MCP012: Path Traversal (76% of servers)"
	@echo "  - MCP013: Shell Execution (70% of servers)"
	@echo "  - MCP017: SSRF (75% of servers)"
	@echo "  - MCP044: Command Injection (70% of servers)"
	@echo ""
	python3 test/integration_test.py

# Run integration tests (alias for test-security)
test-integration: test-security

# Clean build artifacts
clean:
	cargo clean
	rm -rf dist/

# Install locally
install: release
	cargo install --path crates/mcpjail-cli

# Format code
fmt:
	cargo fmt

# Lint code
lint:
	cargo clippy -- -D warnings

# Build for all platforms (requires cross)
cross-all: cross-linux cross-macos cross-windows

# Linux builds
cross-linux:
	@echo "Building for Linux x86_64..."
	cargo build --release --target x86_64-unknown-linux-gnu
	@echo "Building for Linux ARM64..."
	cross build --release --target aarch64-unknown-linux-gnu

# macOS builds (run on macOS)
cross-macos:
	@echo "Building for macOS x86_64..."
	cargo build --release --target x86_64-apple-darwin
	@echo "Building for macOS ARM64 (Apple Silicon)..."
	cargo build --release --target aarch64-apple-darwin

# Windows builds
cross-windows:
	@echo "Building for Windows x86_64..."
	cross build --release --target x86_64-pc-windows-msvc

# Create distribution packages
dist: release
	@mkdir -p dist
	@echo "Creating distribution packages..."
	@if [ "$$(uname)" = "Linux" ]; then \
		cp target/release/mcpjail dist/mcpjail-linux-x86_64; \
		chmod +x dist/mcpjail-linux-x86_64; \
		tar -czvf dist/mcpjail-linux-x86_64.tar.gz -C dist mcpjail-linux-x86_64; \
	elif [ "$$(uname)" = "Darwin" ]; then \
		cp target/release/mcpjail dist/mcpjail-macos-$$(uname -m); \
		chmod +x dist/mcpjail-macos-$$(uname -m); \
		tar -czvf dist/mcpjail-macos-$$(uname -m).tar.gz -C dist mcpjail-macos-$$(uname -m); \
	fi
	@echo "Distribution packages created in dist/"

# Generate checksums
checksums:
	@cd dist && sha256sum * > SHA256SUMS

# Help
help:
	@echo "MCP Jail - Secure MCP Server Sandbox"
	@echo "https://mcpjail.com"
	@echo ""
	@echo "Targets:"
	@echo "  make build           - Build debug version"
	@echo "  make release         - Build release version"
	@echo "  make test            - Run all tests (unit + security)"
	@echo "  make test-unit       - Run Rust unit tests only"
	@echo "  make test-security   - Run security integration tests"
	@echo "  make install         - Install locally"
	@echo "  make clean           - Clean build artifacts"
	@echo "  make fmt             - Format code"
	@echo "  make lint            - Lint code"
	@echo "  make dist            - Create distribution packages"
	@echo "  make cross-all       - Build for all platforms (requires cross)"
	@echo ""
	@echo "Testing:"
	@echo "  Security tests validate blocking of real vulnerabilities:"
	@echo "  - MCP012: Path Traversal (76% of 501 audited servers)"
	@echo "  - MCP013: Shell Execution (70% of servers)"
	@echo "  - MCP017: SSRF (75% of servers)"
	@echo "  - MCP044: Command Injection (70% of servers)"
	@echo ""
	@echo "Platform builds:"
	@echo "  make cross-linux     - Build for Linux"
	@echo "  make cross-macos     - Build for macOS (run on macOS)"
	@echo "  make cross-windows   - Build for Windows"
