#!/usr/bin/env python3
"""
Mock MCP Server for testing MCPBox security features.
This server intentionally exposes dangerous capabilities to test blocking.
"""

import json
import sys

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
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "mock-vulnerable-mcp",
                "version": "1.0.0"
            }
        }
    }

def handle_tools_list(request):
    """Return list of tools including dangerous ones."""
    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "result": {
            "tools": [
                {
                    "name": "read_file",
                    "description": "Read a file from the filesystem",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "Path to the file"}
                        },
                        "required": ["path"]
                    }
                },
                {
                    "name": "execute_command",
                    "description": "Execute a shell command",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "command": {"type": "string", "description": "Command to execute"}
                        },
                        "required": ["command"]
                    }
                },
                {
                    "name": "fetch_url",
                    "description": "Fetch content from a URL",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "url": {"type": "string", "description": "URL to fetch"}
                        },
                        "required": ["url"]
                    }
                },
                {
                    "name": "write_file",
                    "description": "Write content to a file",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string", "description": "Path to write"},
                            "content": {"type": "string", "description": "Content to write"}
                        },
                        "required": ["path", "content"]
                    }
                }
            ]
        }
    }

def handle_tools_call(request):
    """Handle tool calls - simulates execution."""
    params = request.get("params", {})
    tool_name = params.get("name", "")
    arguments = params.get("arguments", {})

    # Simulate responses (in a real vulnerable server, these would execute)
    if tool_name == "read_file":
        path = arguments.get("path", "")
        # Simulate returning sensitive data
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"Contents of {path}:\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nGITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                    }
                ]
            }
        }

    elif tool_name == "execute_command":
        command = arguments.get("command", "")
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"Executed: {command}\nOutput: (simulated execution)"
                    }
                ]
            }
        }

    elif tool_name == "fetch_url":
        url = arguments.get("url", "")
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"Fetched from {url}:\n<html>...</html>"
                    }
                ]
            }
        }

    elif tool_name == "write_file":
        path = arguments.get("path", "")
        return {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": f"Wrote to {path}"
                    }
                ]
            }
        }

    return {
        "jsonrpc": "2.0",
        "id": request.get("id"),
        "error": {
            "code": -32601,
            "message": f"Unknown tool: {tool_name}"
        }
    }

def main():
    """Main loop."""
    sys.stderr.write("Mock MCP Server started\n")
    sys.stderr.flush()

    while True:
        try:
            request = read_request()
            if request is None:
                break

            method = request.get("method", "")
            sys.stderr.write(f"Received: {method}\n")
            sys.stderr.flush()

            if method == "initialize":
                response = handle_initialize(request)
            elif method == "tools/list":
                response = handle_tools_list(request)
            elif method == "tools/call":
                response = handle_tools_call(request)
            elif method == "ping":
                response = {"jsonrpc": "2.0", "id": request.get("id"), "result": {}}
            else:
                response = {
                    "jsonrpc": "2.0",
                    "id": request.get("id"),
                    "error": {"code": -32601, "message": f"Method not found: {method}"}
                }

            write_response(response)

        except json.JSONDecodeError as e:
            sys.stderr.write(f"JSON parse error: {e}\n")
            sys.stderr.flush()
        except Exception as e:
            sys.stderr.write(f"Error: {e}\n")
            sys.stderr.flush()

if __name__ == "__main__":
    main()
