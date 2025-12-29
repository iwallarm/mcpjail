//! Response filtering and sanitization

use serde_json::Value;
use tracing::debug;

/// Filter sensitive data from responses
pub struct ResponseFilter {
    /// Patterns that indicate sensitive data
    sensitive_patterns: Vec<SensitivePattern>,
    /// Keys to redact completely
    redact_keys: Vec<String>,
}

struct SensitivePattern {
    name: &'static str,
    prefix: &'static str,
    min_length: usize,
}

impl Default for ResponseFilter {
    fn default() -> Self {
        Self {
            sensitive_patterns: vec![
                SensitivePattern { name: "AWS Access Key", prefix: "AKIA", min_length: 20 },
                SensitivePattern { name: "AWS Secret Key", prefix: "", min_length: 40 },
                SensitivePattern { name: "GitHub Token", prefix: "ghp_", min_length: 36 },
                SensitivePattern { name: "GitHub Token", prefix: "ghs_", min_length: 36 },
                SensitivePattern { name: "GitHub Token", prefix: "ghr_", min_length: 36 },
                SensitivePattern { name: "GitLab Token", prefix: "glpat-", min_length: 20 },
                SensitivePattern { name: "Slack Token", prefix: "xox", min_length: 40 },
                SensitivePattern { name: "OpenAI Key", prefix: "sk-", min_length: 40 },
                SensitivePattern { name: "Anthropic Key", prefix: "sk-ant-", min_length: 40 },
            ],
            redact_keys: vec![
                "password".to_string(),
                "secret".to_string(),
                "token".to_string(),
                "api_key".to_string(),
                "apikey".to_string(),
                "api-key".to_string(),
                "private_key".to_string(),
                "privatekey".to_string(),
                "private-key".to_string(),
                "access_token".to_string(),
                "accesstoken".to_string(),
                "refresh_token".to_string(),
                "auth".to_string(),
                "authorization".to_string(),
                "credential".to_string(),
                "credentials".to_string(),
            ],
        }
    }
}

impl ResponseFilter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Filter a response, redacting sensitive data
    pub fn filter(&self, value: &mut Value) {
        self.filter_recursive(value);
    }

    fn filter_recursive(&self, value: &mut Value) {
        match value {
            Value::Object(map) => {
                for (key, val) in map.iter_mut() {
                    // Check if key indicates sensitive data
                    let key_lower = key.to_lowercase();
                    if self.redact_keys.iter().any(|k| key_lower.contains(k)) {
                        if let Value::String(s) = val {
                            if !s.is_empty() {
                                debug!("Redacting sensitive key: {}", key);
                                *val = Value::String("[REDACTED]".to_string());
                            }
                        }
                    } else {
                        // Check string values for sensitive patterns
                        if let Value::String(s) = val {
                            if let Some(pattern) = self.detect_sensitive_pattern(s) {
                                debug!("Redacting {} in key: {}", pattern, key);
                                *val = Value::String(format!("[REDACTED: {}]", pattern));
                            }
                        }
                        // Recurse
                        self.filter_recursive(val);
                    }
                }
            }
            Value::Array(arr) => {
                for item in arr.iter_mut() {
                    self.filter_recursive(item);
                }
            }
            Value::String(s) => {
                if let Some(pattern) = self.detect_sensitive_pattern(s) {
                    debug!("Redacting {} pattern", pattern);
                    *value = Value::String(format!("[REDACTED: {}]", pattern));
                }
            }
            _ => {}
        }
    }

    /// Detect if a string matches a sensitive pattern
    fn detect_sensitive_pattern(&self, value: &str) -> Option<&'static str> {
        // Skip short strings
        if value.len() < 20 {
            return None;
        }

        // Check known prefixes
        for pattern in &self.sensitive_patterns {
            if !pattern.prefix.is_empty() && value.starts_with(pattern.prefix) {
                if value.len() >= pattern.min_length {
                    return Some(pattern.name);
                }
            }
        }

        // Check for high-entropy strings that might be secrets
        if self.is_high_entropy(value) && value.len() >= 32 {
            // Additional heuristics for secrets
            if value.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
                // Looks like a token/key
                return Some("possible secret");
            }
        }

        // Check for JWT tokens
        if is_jwt(value) {
            return Some("JWT token");
        }

        None
    }

    /// Check if a string has high entropy (likely random)
    fn is_high_entropy(&self, value: &str) -> bool {
        if value.len() < 16 {
            return false;
        }

        let mut char_counts = [0u32; 256];
        for byte in value.bytes() {
            char_counts[byte as usize] += 1;
        }

        let len = value.len() as f64;
        let entropy: f64 = char_counts
            .iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum();

        // High entropy threshold (secrets typically > 4.0)
        entropy > 4.0
    }
}

/// Check if a string is a JWT token
fn is_jwt(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 3 {
        return false;
    }

    // Each part should be base64-ish
    parts.iter().all(|part| {
        part.len() >= 4 && part.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '=')
    })
}

/// Sanitize environment variables, keeping only names
pub fn sanitize_env_vars(vars: &std::collections::HashMap<String, String>) -> Vec<String> {
    vars.keys()
        .map(|k| format!("{}=[SET]", k))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_redact_password() {
        let mut value = json!({
            "username": "admin",
            "password": "secret123"
        });

        let filter = ResponseFilter::new();
        filter.filter(&mut value);

        assert_eq!(value["username"], "admin");
        assert_eq!(value["password"], "[REDACTED]");
    }

    #[test]
    fn test_redact_aws_key() {
        let mut value = json!({
            "data": "AKIAIOSFODNN7EXAMPLE"
        });

        let filter = ResponseFilter::new();
        filter.filter(&mut value);

        assert!(value["data"].as_str().unwrap().contains("REDACTED"));
    }

    #[test]
    fn test_redact_github_token() {
        let mut value = json!({
            "token": "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        });

        let filter = ResponseFilter::new();
        filter.filter(&mut value);

        assert!(value["token"].as_str().unwrap().contains("REDACTED"));
    }

    #[test]
    fn test_detect_jwt() {
        assert!(is_jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"));
        assert!(!is_jwt("not.a.jwt"));
        assert!(!is_jwt("hello world"));
    }

    #[test]
    fn test_nested_redaction() {
        let mut value = json!({
            "config": {
                "database": {
                    "password": "db_secret"
                }
            }
        });

        let filter = ResponseFilter::new();
        filter.filter(&mut value);

        assert_eq!(value["config"]["database"]["password"], "[REDACTED]");
    }
}
