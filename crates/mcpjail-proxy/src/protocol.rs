//! MCP Protocol message types

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC 2.0 request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

/// JSON-RPC 2.0 response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// JSON-RPC 2.0 error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    /// Create a success response
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response
    pub fn error(id: Option<Value>, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message,
                data: None,
            }),
        }
    }
}

/// MCP message types
#[derive(Debug, Clone)]
pub enum McpMessage {
    // Client -> Server requests
    Initialize(InitializeRequest),
    ListTools,
    CallTool(CallToolRequest),
    ListResources,
    GetResource(GetResourceRequest),
    ListPrompts,
    GetPrompt(GetPromptRequest),
    Complete(CompleteRequest),
    Ping,

    // Server -> Client notifications
    Notification(NotificationMessage),

    // Unknown/passthrough
    Unknown(JsonRpcRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitializeRequest {
    #[serde(rename = "protocolVersion")]
    pub protocol_version: String,
    pub capabilities: ClientCapabilities,
    #[serde(rename = "clientInfo")]
    pub client_info: ClientInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientCapabilities {
    #[serde(default)]
    pub roots: Option<RootsCapability>,
    #[serde(default)]
    pub sampling: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootsCapability {
    #[serde(rename = "listChanged")]
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallToolRequest {
    pub name: String,
    #[serde(default)]
    pub arguments: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetResourceRequest {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPromptRequest {
    pub name: String,
    #[serde(default)]
    pub arguments: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteRequest {
    pub r#ref: CompleteRef,
    pub argument: CompleteArgument,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteRef {
    pub r#type: String,
    pub name: Option<String>,
    pub uri: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteArgument {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationMessage {
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
}

impl McpMessage {
    /// Parse a JSON-RPC request into an MCP message
    pub fn from_request(request: &JsonRpcRequest) -> Self {
        match request.method.as_str() {
            "initialize" => {
                if let Some(params) = &request.params {
                    if let Ok(init) = serde_json::from_value(params.clone()) {
                        return McpMessage::Initialize(init);
                    }
                }
                McpMessage::Unknown(request.clone())
            }
            "tools/list" => McpMessage::ListTools,
            "tools/call" => {
                if let Some(params) = &request.params {
                    if let Ok(call) = serde_json::from_value(params.clone()) {
                        return McpMessage::CallTool(call);
                    }
                }
                McpMessage::Unknown(request.clone())
            }
            "resources/list" => McpMessage::ListResources,
            "resources/read" => {
                if let Some(params) = &request.params {
                    if let Ok(get) = serde_json::from_value(params.clone()) {
                        return McpMessage::GetResource(get);
                    }
                }
                McpMessage::Unknown(request.clone())
            }
            "prompts/list" => McpMessage::ListPrompts,
            "prompts/get" => {
                if let Some(params) = &request.params {
                    if let Ok(get) = serde_json::from_value(params.clone()) {
                        return McpMessage::GetPrompt(get);
                    }
                }
                McpMessage::Unknown(request.clone())
            }
            "completion/complete" => {
                if let Some(params) = &request.params {
                    if let Ok(complete) = serde_json::from_value(params.clone()) {
                        return McpMessage::Complete(complete);
                    }
                }
                McpMessage::Unknown(request.clone())
            }
            "ping" => McpMessage::Ping,
            method if method.starts_with("notifications/") => {
                McpMessage::Notification(NotificationMessage {
                    method: method.to_string(),
                    params: request.params.clone(),
                })
            }
            _ => McpMessage::Unknown(request.clone()),
        }
    }
}

/// Tool definition from tools/list response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

/// Parse tool definitions from a tools/list response
pub fn parse_tools_response(response: &JsonRpcResponse) -> Vec<ToolDefinition> {
    if let Some(result) = &response.result {
        if let Some(tools) = result.get("tools") {
            if let Ok(tools) = serde_json::from_value::<Vec<ToolDefinition>>(tools.clone()) {
                return tools;
            }
        }
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_call_tool() {
        let json = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/tmp/test.txt"}
            }
        }"#;

        let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
        let msg = McpMessage::from_request(&request);

        match msg {
            McpMessage::CallTool(call) => {
                assert_eq!(call.name, "read_file");
            }
            _ => panic!("Expected CallTool"),
        }
    }

    #[test]
    fn test_parse_initialize() {
        let json = r#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1.0"}
            }
        }"#;

        let request: JsonRpcRequest = serde_json::from_str(json).unwrap();
        let msg = McpMessage::from_request(&request);

        match msg {
            McpMessage::Initialize(init) => {
                assert_eq!(init.protocol_version, "2024-11-05");
            }
            _ => panic!("Expected Initialize"),
        }
    }
}
