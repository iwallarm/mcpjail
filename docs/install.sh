#!/bin/sh
# MCP Jail Installer
# https://mcpjail.com
#
# Usage: curl -fsSL https://mcpjail.com/install.sh | sh

set -e

REPO="iwallarm/mcpjail"
BINARY_NAME="mcpjail"
INSTALL_DIR="/usr/local/bin"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() {
    printf "${BLUE}==>${NC} %s\n" "$1"
}

success() {
    printf "${GREEN}==>${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}Warning:${NC} %s\n" "$1"
}

error() {
    printf "${RED}Error:${NC} %s\n" "$1" >&2
    exit 1
}

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Linux*)     echo "linux" ;;
        Darwin*)    echo "darwin" ;;
        MINGW*|MSYS*|CYGWIN*)
            error "Windows detected. Please use WSL2 or download the binary manually from https://github.com/${REPO}/releases"
            ;;
        *)          error "Unsupported operating system: $(uname -s)" ;;
    esac
}

# Detect architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "x86_64" ;;
        arm64|aarch64)  echo "aarch64" ;;
        *)              error "Unsupported architecture: $(uname -m)" ;;
    esac
}

# Get latest release version
get_latest_version() {
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/'
    else
        error "Neither curl nor wget found. Please install one of them."
    fi
}

# Download file
download() {
    local url="$1"
    local output="$2"

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$url" -o "$output"
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$url" -O "$output"
    else
        error "Neither curl nor wget found. Please install one of them."
    fi
}

# Check for required tools
check_dependencies() {
    if ! command -v tar >/dev/null 2>&1; then
        error "tar is required but not installed."
    fi
}

# Main installation
main() {
    echo ""
    echo "  ╔══════════════════════════════════════╗"
    echo "  ║         MCP Jail Installer           ║"
    echo "  ║   Run MCP servers with zero risk     ║"
    echo "  ╚══════════════════════════════════════╝"
    echo ""

    check_dependencies

    OS=$(detect_os)
    ARCH=$(detect_arch)

    info "Detected: ${OS} (${ARCH})"

    # Build target triple
    case "${OS}" in
        linux)
            TARGET="${ARCH}-unknown-linux-gnu"
            EXT="tar.gz"
            ;;
        darwin)
            TARGET="${ARCH}-apple-darwin"
            EXT="tar.gz"
            ;;
    esac

    info "Fetching latest version..."
    VERSION=$(get_latest_version)

    if [ -z "$VERSION" ]; then
        error "Failed to fetch latest version. Check your internet connection or visit https://github.com/${REPO}/releases"
    fi

    info "Latest version: ${VERSION}"

    # Download URL
    FILENAME="${BINARY_NAME}-${TARGET}.${EXT}"
    URL="https://github.com/${REPO}/releases/download/${VERSION}/${FILENAME}"

    info "Downloading ${FILENAME}..."

    # Create temp directory
    TMP_DIR=$(mktemp -d)
    trap "rm -rf ${TMP_DIR}" EXIT

    download "$URL" "${TMP_DIR}/${FILENAME}"

    info "Extracting..."
    tar -xzf "${TMP_DIR}/${FILENAME}" -C "${TMP_DIR}"

    # Find the binary
    if [ -f "${TMP_DIR}/${BINARY_NAME}" ]; then
        BINARY_PATH="${TMP_DIR}/${BINARY_NAME}"
    elif [ -f "${TMP_DIR}/${BINARY_NAME}-${TARGET}/${BINARY_NAME}" ]; then
        BINARY_PATH="${TMP_DIR}/${BINARY_NAME}-${TARGET}/${BINARY_NAME}"
    else
        # Search for it
        BINARY_PATH=$(find "${TMP_DIR}" -name "${BINARY_NAME}" -type f | head -1)
        if [ -z "$BINARY_PATH" ]; then
            error "Could not find ${BINARY_NAME} binary in archive"
        fi
    fi

    # Check if we can write to install dir
    if [ -w "${INSTALL_DIR}" ]; then
        info "Installing to ${INSTALL_DIR}..."
        cp "$BINARY_PATH" "${INSTALL_DIR}/${BINARY_NAME}"
        chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    else
        info "Installing to ${INSTALL_DIR} (requires sudo)..."
        sudo cp "$BINARY_PATH" "${INSTALL_DIR}/${BINARY_NAME}"
        sudo chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    # Verify installation
    if command -v ${BINARY_NAME} >/dev/null 2>&1; then
        success "MCP Jail ${VERSION} installed successfully!"
        echo ""
        echo "  Get started:"
        echo "    ${BINARY_NAME} --help"
        echo ""
        echo "  Example usage:"
        echo "    ${BINARY_NAME} npx -y @modelcontextprotocol/server-filesystem /workspace"
        echo ""
        echo "  Documentation:"
        echo "    https://mcpjail.com"
        echo ""
    else
        warn "Installation completed but '${BINARY_NAME}' not found in PATH."
        echo "  You may need to add ${INSTALL_DIR} to your PATH:"
        echo "    export PATH=\"\$PATH:${INSTALL_DIR}\""
    fi
}

# Run main
main "$@"
