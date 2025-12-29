#!/usr/bin/env python3
"""
Test script to send various MCP requests and demonstrate mcpbox blocking.
"""

import json
import subprocess
import sys
import os

# Test requests - mix of safe and dangerous
TEST_REQUESTS = [
    # 1. Initialize - always allowed
    {
        "name": "Initialize (always allowed)",
        "request": {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}
            }
        },
        "should_block": False
    },

    # 2. List tools - always allowed
    {
        "name": "List tools (always allowed)",
        "request": {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        },
        "should_block": False
    },

    # 3. Execute command - SHOULD BE BLOCKED (dangerous tool)
    {
        "name": "Execute command (BLOCKED - dangerous tool)",
        "request": {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "execute_command",
                "arguments": {"command": "cat /etc/passwd"}
            }
        },
        "should_block": True,
        "reason": "execute_command is blocked by strict policy"
    },

    # 4. Read file with path traversal - SHOULD BE BLOCKED
    {
        "name": "Read file with path traversal (BLOCKED)",
        "request": {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "../../../etc/passwd"}
            }
        },
        "should_block": True,
        "reason": "Path traversal detected (..)"
    },

    # 5. Read sensitive file - SHOULD BE BLOCKED (path not in allowed mounts)
    {
        "name": "Read /etc/shadow (BLOCKED - path not allowed)",
        "request": {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/etc/shadow"}
            }
        },
        "should_block": True,
        "reason": "Path /etc/shadow not in allowed mounts"
    },

    # 6. SSRF to internal network - SHOULD BE BLOCKED
    {
        "name": "Fetch localhost (BLOCKED - SSRF to internal network)",
        "request": {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "fetch_url",
                "arguments": {"url": "http://localhost:8080/admin"}
            }
        },
        "should_block": True,
        "reason": "SSRF attempt to internal network (localhost)"
    },

    # 7. SSRF to cloud metadata - SHOULD BE BLOCKED
    {
        "name": "Fetch AWS metadata (BLOCKED - cloud metadata SSRF)",
        "request": {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "fetch_url",
                "arguments": {"url": "http://169.254.169.254/latest/meta-data/"}
            }
        },
        "should_block": True,
        "reason": "SSRF attempt to cloud metadata endpoint"
    },

    # 8. Shell injection attempt - SHOULD BE BLOCKED
    {
        "name": "Shell tool (BLOCKED - shell in tool name)",
        "request": {
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "run_shell",
                "arguments": {"command": "whoami"}
            }
        },
        "should_block": True,
        "reason": "Tool name contains 'shell' - blocked by policy"
    },

    # 9. Ping - always allowed
    {
        "name": "Ping (always allowed)",
        "request": {
            "jsonrpc": "2.0",
            "id": 9,
            "method": "ping"
        },
        "should_block": False
    },

    # 10. Read /tmp file - allowed (in strict policy mounts)
    {
        "name": "Read /tmp/test.txt (allowed - /tmp is mounted)",
        "request": {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/tmp/test.txt"}
            }
        },
        "should_block": False
    },
]

def print_header(text):
    print("\n" + "=" * 70)
    print(f" {text}")
    print("=" * 70)

def print_result(name, blocked, expected_block, reason=None, response=None):
    status = "BLOCKED" if blocked else "ALLOWED"
    expected = "BLOCKED" if expected_block else "ALLOWED"

    if blocked == expected_block:
        result = "\033[32m✓ PASS\033[0m"
    else:
        result = "\033[31m✗ FAIL\033[0m"

    print(f"\n{result} {name}")
    print(f"   Status: {status} (expected: {expected})")
    if reason and blocked:
        print(f"   Reason: {reason}")
    if response:
        # Truncate long responses
        resp_str = json.dumps(response)
        if len(resp_str) > 100:
            resp_str = resp_str[:100] + "..."
        print(f"   Response: {resp_str}")

def main():
    print_header("MCPBox Security Test Suite")
    print("\nThis test sends various MCP requests through mcpbox and validates")
    print("that dangerous requests are blocked while safe ones are allowed.")
    print("\nPolicy: strict (no network, blocked exec tools, limited paths)")

    # Build mcpbox first
    print("\n[*] Building mcpbox...")
    result = subprocess.run(
        ["cargo", "build", "--release"],
        cwd="/home/claude/mcpbox",
        capture_output=True,
        text=True
    )
    if result.returncode != 0:
        print(f"Build failed: {result.stderr}")
        sys.exit(1)
    print("[*] Build complete")

    mcpbox = "/home/claude/mcpbox/target/release/mcpbox"
    mock_server = "/home/claude/mcpbox/test/mock_mcp_server.py"

    print_header("Running Security Tests")

    passed = 0
    failed = 0

    for test in TEST_REQUESTS:
        name = test["name"]
        request = test["request"]
        should_block = test["should_block"]
        reason = test.get("reason", "")

        # Start mcpbox with the mock server
        proc = subprocess.Popen(
            [mcpbox, "--policy", "strict", "--verbose", "python3", mock_server],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        try:
            # Send request
            request_json = json.dumps(request)
            stdout, stderr = proc.communicate(input=request_json + "\n", timeout=5)

            # Parse response
            response = None
            blocked = False
            block_reason = ""

            for line in stdout.strip().split("\n"):
                if line:
                    try:
                        resp = json.loads(line)
                        response = resp
                        # Check if it's an error response from mcpbox
                        if "error" in resp:
                            error_msg = resp["error"].get("message", "")
                            if "MCPBox policy violation" in error_msg:
                                blocked = True
                                block_reason = error_msg
                    except json.JSONDecodeError:
                        pass

            # Check stderr for block messages
            if "WARN" in stderr or "blocked" in stderr.lower():
                if not blocked:
                    blocked = True
                    for line in stderr.split("\n"):
                        if "blocked" in line.lower() or "WARN" in line:
                            block_reason = line.strip()
                            break

            print_result(name, blocked, should_block, block_reason or reason, response)

            if blocked == should_block:
                passed += 1
            else:
                failed += 1

        except subprocess.TimeoutExpired:
            proc.kill()
            print(f"\n\033[33m⚠ TIMEOUT\033[0m {name}")
            failed += 1
        except Exception as e:
            print(f"\n\033[31m✗ ERROR\033[0m {name}: {e}")
            failed += 1

    print_header("Test Summary")
    print(f"\n  Passed: {passed}")
    print(f"  Failed: {failed}")
    print(f"  Total:  {passed + failed}")

    if failed == 0:
        print("\n\033[32m✓ All security tests passed!\033[0m")
    else:
        print(f"\n\033[31m✗ {failed} test(s) failed\033[0m")

    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
