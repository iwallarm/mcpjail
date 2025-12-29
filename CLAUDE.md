# MCP Jail - Secure MCP Server Sandbox

**Website:** https://mcpjail.com

## Product Vision

MCP Jail is a drop-in replacement for running MCP servers that provides complete isolation and security enforcement. Instead of running `npx @modelcontextprotocol/server-filesystem`, users run `mcpjail npx @modelcontextprotocol/server-filesystem` and get automatic Docker containerization with a Rust-based MCP protocol proxy that enforces security policies.

**Tagline:** "Run any MCP server with zero trust, zero risk."

## Problem Statement

Based on our security audit of 501 MCP servers:
- 96.4% contain exploitable vulnerabilities
- 70.3% have shell execution capabilities
- 93.4% use unpinned dependencies (supply chain risk)
- 75.4% have unrestricted network access

Current MCP clients (Claude Desktop, Cursor, etc.) run MCP servers with full user privileges - if compromised, attackers get complete access to the developer's machine.

## Solution Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         User's Machine                          │
│                                                                 │
│  ┌─────────────┐     ┌──────────────────────────────────────┐  │
│  │ MCP Client  │────▶│           MCP Jail Proxy             │  │
│  │ (Claude,    │     │         (Rust, stdio)                │  │
│  │  Cursor)    │◀────│                                      │  │
│  └─────────────┘     │  • MCP Protocol Validation           │  │
│                      │  • Request/Response Filtering        │  │
│                      │  • Policy Enforcement                │  │
│                      │  • Audit Logging                     │  │
│                      └──────────────┬───────────────────────┘  │
│                                     │ stdio over docker exec   │
│                      ┌──────────────▼───────────────────────┐  │
│                      │     Docker Container (Hardened)      │  │
│                      │                                      │  │
│                      │  ┌────────────────────────────────┐  │  │
│                      │  │        MCP Server              │  │  │
│                      │  │   (npx/python/node/etc)        │  │  │
│                      │  └────────────────────────────────┘  │  │
│                      │                                      │  │
│                      │  Restrictions:                       │  │
│                      │  • No network (--network=none)       │  │
│                      │  • Read-only rootfs                  │  │
│                      │  • Dropped capabilities              │  │
│                      │  • Seccomp profile                   │  │
│                      │  • No privileged operations          │  │
│                      │  • Resource limits (CPU/mem)         │  │
│                      │  • Mounted paths only (read-only)    │  │
│                      └──────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. MCP Jail CLI (`mcpjail`)

The main entry point. Written in Rust for performance and security.

```bash
# Basic usage - wraps any MCP server command
mcpjail npx -y @modelcontextprotocol/server-filesystem /path/to/allowed

# With explicit policy
mcpjail --policy strict npx -y @some/mcp-server

# Allow specific network access
mcpjail --allow-host api.example.com python -m mcp_server

# Mount additional paths
mcpjail --mount /data:ro npx -y @some/mcp-server

# Generate policy from dry run
mcpjail --learn npx -y @some/mcp-server
```

### 2. MCP Protocol Proxy (`mcpjail-proxy`)

Rust-based proxy that sits between MCP client and containerized server.

**Responsibilities:**
- Parse and validate all MCP JSON-RPC messages
- Enforce tool allowlists/denylists
- Filter sensitive data from responses
- Block path traversal attempts
- Prevent SSRF via URL validation
- Rate limit requests
- Audit log all operations

### 3. Docker Runtime (`mcpjail-runtime`)

Hardened container configuration generator.

**Security Controls:**
- `--network=none` by default
- `--read-only` filesystem
- `--cap-drop=ALL`
- `--security-opt=no-new-privileges`
- Custom seccomp profile blocking dangerous syscalls
- AppArmor/SELinux profiles
- Resource limits (memory, CPU, PIDs)
- Temporary `/tmp` with size limits

### 4. Policy Engine (`mcpjail-policy`)

YAML/TOML-based policy definitions.

```yaml
# ~/.mcpjail/policies/strict.yaml
name: strict
version: 1

network:
  mode: none  # none | allowlist | host

filesystem:
  mode: explicit  # none | explicit | workspace
  mounts:
    - path: /workspace
      mode: ro
    - path: /tmp
      mode: rw
      size: 100M

tools:
  mode: allowlist
  allowed:
    - read_file
    - list_directory
  blocked:
    - execute_command
    - write_file

resources:
  memory: 512M
  cpu: 1.0
  pids: 100
  timeout: 300s

audit:
  enabled: true
  level: info
  destination: ~/.mcpjail/logs/
```

## Security Mitigations

Based on our MCP security research, MCP Jail blocks these attack vectors:

### MCP001: Unpinned Dependencies
- Container uses pinned base images with SHA256 digests
- Runtime dependencies installed at build time, not runtime
- No `npm install` or `pip install` during execution

### MCP007: Hardcoded Secrets
- Environment variables sanitized before passing to container
- Only explicitly allowed env vars passed through
- No access to host's ~/.aws, ~/.ssh, etc.

### MCP012: Broad Filesystem Access
- Only explicitly mounted paths accessible
- Default: no host filesystem access
- Path traversal blocked at proxy level

### MCP013: Shell/Exec Capability
- Seccomp blocks execve for spawning new processes
- Or: tool filtering blocks execute_* tools at proxy level
- Container has no shell by default (distroless base)

### MCP017: Unrestricted Network
- `--network=none` by default
- Allowlist mode for specific hosts only
- DNS filtered to prevent exfiltration

### Additional Protections
- **Supply Chain:** Pre-built, signed container images
- **Resource Exhaustion:** CPU/memory/PID limits
- **Privilege Escalation:** No root, no capabilities
- **Container Escape:** Hardened seccomp/AppArmor

## Implementation Plan

### Phase 1: Core CLI & Docker Runtime
1. Rust CLI that wraps commands in Docker
2. Hardened container configuration
3. Basic stdio passthrough
4. Simple policy file support

### Phase 2: MCP Protocol Proxy
1. JSON-RPC parser for MCP protocol
2. Request/response validation
3. Tool filtering
4. Path validation in arguments
5. Audit logging

### Phase 3: Advanced Policies
1. Per-server policy configurations
2. Policy learning mode
3. Policy inheritance
4. Built-in policy templates

### Phase 4: Ecosystem Integration
1. Claude Desktop configuration generator
2. Cursor integration
3. VS Code extension
4. CI/CD scanning integration

## Technical Specifications

### Rust Crates to Use
```toml
[dependencies]
# CLI
clap = "4"
tokio = { version = "1", features = ["full"] }

# Docker
bollard = "0.15"  # Docker API client

# MCP Protocol
serde = { version = "1", features = ["derive"] }
serde_json = "1"

# Logging/Tracing
tracing = "0.1"
tracing-subscriber = "0.3"

# Policy
config = "0.13"
schemars = "0.8"  # JSON schema for policies

# Security
ring = "0.17"  # For any crypto needs
```

### Container Base Images

```dockerfile
# Distroless for minimal attack surface
FROM gcr.io/distroless/nodejs20-debian12@sha256:...
# OR
FROM gcr.io/distroless/python3-debian12@sha256:...

# No shell, no package manager, minimal binaries
```

### MCP Protocol Messages to Validate

```rust
// All MCP messages must be validated
enum McpMessage {
    // Requests from client
    Initialize(InitializeRequest),
    CallTool(CallToolRequest),
    ListTools(ListToolsRequest),
    GetResource(GetResourceRequest),
    ListResources(ListResourcesRequest),

    // Responses from server
    InitializeResult(InitializeResult),
    CallToolResult(CallToolResult),
    // ... etc
}

// Validation rules
impl McpMessage {
    fn validate(&self, policy: &Policy) -> Result<(), ValidationError> {
        match self {
            McpMessage::CallTool(req) => {
                // Check tool is allowed
                if !policy.tools.is_allowed(&req.name) {
                    return Err(ValidationError::ToolBlocked(req.name));
                }
                // Validate arguments (paths, URLs, etc)
                validate_tool_args(&req.name, &req.arguments, policy)?;
                Ok(())
            }
            // ... other cases
        }
    }
}
```

### Seccomp Profile

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {
      "names": ["read", "write", "close", "fstat", "mmap", "mprotect",
                "munmap", "brk", "rt_sigaction", "rt_sigprocmask",
                "ioctl", "access", "pipe", "dup", "dup2", "getpid",
                "socket", "connect", "sendto", "recvfrom", "shutdown",
                "fcntl", "flock", "fsync", "fdatasync", "ftruncate",
                "getdents", "getcwd", "chdir", "openat", "mkdirat",
                "newfstatat", "unlinkat", "readlinkat", "faccessat",
                "clock_gettime", "futex", "epoll_create1", "epoll_ctl",
                "epoll_pwait", "eventfd2", "getrandom"],
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "names": ["execve", "execveat"],
      "action": "SCMP_ACT_ERRNO",
      "comment": "Block process spawning"
    },
    {
      "names": ["ptrace", "process_vm_readv", "process_vm_writev"],
      "action": "SCMP_ACT_ERRNO",
      "comment": "Block debugging/inspection"
    }
  ]
}
```

## Usage Examples

### Basic Filesystem Server
```bash
# Before (unsafe)
npx -y @modelcontextprotocol/server-filesystem /home/user

# After (sandboxed)
mcpjail npx -y @modelcontextprotocol/server-filesystem /workspace
# Mounts /home/user as /workspace inside container, read-only
```

### Database Server with Network
```bash
# Allow only database host
mcpjail --allow-host db.example.com:5432 \
  python -m mcp_postgres_server
```

### Development with Write Access
```bash
# Mount current directory with write access
mcpjail --mount .:/workspace:rw \
  npx -y @some/code-editor-mcp
```

### Claude Desktop Configuration
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcpjail",
      "args": [
        "--policy", "readonly",
        "npx", "-y", "@modelcontextprotocol/server-filesystem",
        "/workspace"
      ],
      "env": {}
    }
  }
}
```

## Project Structure

```
mcpjail/
├── CLAUDE.md              # This file
├── Cargo.toml             # Workspace manifest
├── Cargo.lock
├── crates/
│   ├── mcpjail-cli/       # Main CLI binary
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── cli.rs
│   │       └── commands/
│   ├── mcpjail-proxy/     # MCP protocol proxy
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── protocol.rs
│   │       ├── validator.rs
│   │       └── filter.rs
│   ├── mcpjail-runtime/   # Docker runtime management
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── container.rs
│   │       ├── security.rs
│   │       └── mounts.rs
│   └── mcpjail-policy/    # Policy engine
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           ├── parser.rs
│           └── builtin.rs
├── policies/              # Built-in policy templates
│   ├── strict.yaml
│   ├── readonly.yaml
│   ├── development.yaml
│   └── network-isolated.yaml
├── containers/            # Container definitions
│   ├── Dockerfile.node
│   ├── Dockerfile.python
│   └── Dockerfile.base
├── seccomp/               # Seccomp profiles
│   └── default.json
└── tests/
    ├── integration/
    └── e2e/
```

## Development Commands

```bash
# Build all crates
cargo build --release

# Run tests
cargo test

# Run with debug logging
RUST_LOG=debug cargo run -- npx -y @some/mcp-server

# Build container images
docker build -f containers/Dockerfile.node -t mcpjail-node:latest .

# Run integration tests
cargo test --test integration
```

## Success Criteria

1. **Zero Trust:** MCP server cannot access anything not explicitly allowed
2. **Transparent:** Works as drop-in replacement for direct execution
3. **Performant:** <10ms overhead for message proxying
4. **Observable:** Complete audit log of all MCP operations
5. **Configurable:** Policies for any security/functionality tradeoff

## Non-Goals (v1)

- GUI configuration tool
- Remote/cloud execution
- Multi-tenant server management
- Windows native support (WSL2 required)
- Custom container registries

## Security Threat Model

### In Scope
- Malicious MCP server code
- Supply chain attacks on dependencies
- Container escape attempts
- Data exfiltration via network
- Filesystem access outside mounts
- Resource exhaustion attacks
- Protocol-level attacks

### Out of Scope
- Kernel vulnerabilities
- Docker daemon compromise
- Physical access attacks
- Side-channel attacks
- Social engineering

## References

- **MCP Jail Website:** https://mcpjail.com
- MCP Specification: https://modelcontextprotocol.io/specification
- Docker Security: https://docs.docker.com/engine/security/
- Seccomp: https://man7.org/linux/man-pages/man2/seccomp.2.html
- Our MCP Security Audit: /home/claude/postman-mcp-guard/mcp_analysis_report/
