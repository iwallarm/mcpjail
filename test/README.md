# MCP Jail Security Test Suite

This test suite proves that MCP Jail effectively blocks real-world vulnerabilities
found in our security audit of **501 MCP servers**.

## Test Philosophy

The tests follow a **"before and after"** approach:

1. **Without MCP Jail**: Run attack directly against vulnerable server → **Attack SUCCEEDS**
2. **With MCP Jail**: Run same attack through mcpjail → **Attack BLOCKED**

This provides definitive proof that MCP Jail works.

## Vulnerabilities Tested

Based on our audit findings, we test blocking of:

| ID | Vulnerability | Prevalence | Description |
|-----|---------------|------------|-------------|
| MCP012 | Path Traversal | 76.0% | `../../etc/passwd` attacks |
| MCP013 | Shell Execution | 70.3% | Tools that spawn shells |
| MCP017 | SSRF | 75.4% | Internal network/cloud metadata access |
| MCP044 | Command Injection | 70.3% | Shell injection via `os.system()` |
| MCP007 | Secrets Exposure | 29.3% | Hardcoded API keys leaking |
| MCP021 | Insecure Deserial. | CRITICAL | Pickle RCE vulnerabilities |
| MCP041 | Dynamic Execution | CRITICAL | `eval()` / `exec()` RCE |

## Running Tests

```bash
# Run all tests
make test

# Run only Rust unit tests
make test-unit

# Run security integration tests
make test-security

# Or directly:
python3 test/integration_test.py
```

## Test Files

### `vulnerable_mcp_server.py`

An intentionally vulnerable MCP server that implements real vulnerability patterns
found during our audit:

- **read_file**: No path validation (MCP012)
- **write_file**: Arbitrary file write (MCP012)
- **execute_command**: Shell injection via `shell=True` (MCP044)
- **search_files**: Command injection in find pattern (MCP044)
- **fetch_url**: No SSRF protection (MCP017)
- **load_data**: Pickle deserialization RCE (MCP021)
- **evaluate**: `eval()` with user input (MCP041)
- **get_config**: Exposes hardcoded secrets (MCP007)

### `integration_test.py`

The main test runner that:

1. Sends attack payloads directly to the vulnerable server
2. Verifies attacks succeed (proving the vulnerability exists)
3. Sends same payloads through mcpjail
4. Verifies attacks are blocked
5. Reports pass/fail for each vulnerability class

### Rust Unit Tests

Located in `crates/mcpjail-proxy/src/validator.rs`:

- `test_mcp012_*`: Path traversal blocking tests
- `test_mcp017_*`: SSRF blocking tests
- `test_mcp044_*`: Command injection blocking tests
- `test_mcp013_*`: Shell execution blocking tests

## Attack Payloads Tested

### Path Traversal (MCP012)

```json
{"name": "read_file", "arguments": {"path": "../../../etc/passwd"}}
{"name": "read_file", "arguments": {"path": "/etc/shadow"}}
{"name": "read_file", "arguments": {"path": "../../.aws/credentials"}}
```

### Command Injection (MCP044)

```json
{"name": "execute_command", "arguments": {"command": "id && whoami"}}
{"name": "execute_command", "arguments": {"command": "cat /etc/passwd"}}
{"name": "search_files", "arguments": {"pattern": "'; cat /etc/passwd #"}}
```

### SSRF (MCP017)

```json
{"name": "fetch_url", "arguments": {"url": "http://169.254.169.254/latest/meta-data/"}}
{"name": "fetch_url", "arguments": {"url": "http://localhost:8080/admin"}}
{"name": "fetch_url", "arguments": {"url": "http://192.168.1.1/"}}
```

### Shell Tools (MCP013)

```json
{"name": "run_shell", "arguments": {"command": "whoami"}}
{"name": "bash", "arguments": {"script": "ls -la"}}
{"name": "exec", "arguments": {"cmd": "id"}}
```

## Expected Output

```
==============================================================================
 MCP Jail Security Integration Tests
==============================================================================

This test suite validates that MCP Jail effectively blocks
real vulnerabilities found in 501 MCP servers.

==============================================================================
 MCP012: Path Traversal (76.0% of servers)
==============================================================================

✓ [PASS] Path Traversal - Read /etc/passwd
   Vulnerability: MCP012 - Attempt to read /etc/passwd using path traversal
   Direct (no jail): VULNERABLE
   Through mcpjail: BLOCKED

✓ [PASS] Path Traversal - Read AWS Credentials
   Vulnerability: MCP012 - Attempt to steal AWS credentials via path traversal
   Direct (no jail): VULNERABLE
   Through mcpjail: BLOCKED

...

==============================================================================
 Test Summary
==============================================================================

  Results by Vulnerability Type:
    MCP007: 1/1 ALL BLOCKED
    MCP012: 3/3 ALL BLOCKED
    MCP013: 2/2 ALL BLOCKED
    MCP017: 3/3 ALL BLOCKED
    MCP041: 2/2 ALL BLOCKED
    MCP044: 3/3 ALL BLOCKED

  Overall:
    Passed: 14
    Failed: 0
    Total:  14

  ✓ All security tests passed!
    MCP Jail successfully blocks all tested attack vectors.
```

## Adding New Tests

To add a new vulnerability test:

1. Add the vulnerable pattern to `vulnerable_mcp_server.py`
2. Add a `TestCase` to `integration_test.py`:

```python
TestCase(
    name="New Vulnerability Test",
    mcp_id="MCPXXX",
    description="Description of the attack",
    request={
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "vulnerable_tool",
            "arguments": {"payload": "attack string"}
        }
    },
    attack_indicator="string_that_proves_attack_worked",
    block_indicator="string_in_error_when_blocked"
)
```

3. Add corresponding Rust unit tests in `validator.rs`

## References

- [MCP Security Audit Report](/home/claude/postman-mcp-guard/mcp_analysis_report/)
- [INSECURE_CODE_PATTERNS.md](/home/claude/postman-mcp-guard/mcp_analysis_report/INSECURE_CODE_PATTERNS.md)
- [MCP-RISKS.md](/home/claude/postman-mcp-guard/MCP-RISKS.md)
