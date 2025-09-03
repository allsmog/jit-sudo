//! JIT Sudo Core Library
//! 
//! Provides JWT grant verification, policy evaluation, and audit logging

pub mod grant;
pub mod policy;
pub mod audit;
pub mod ffi;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum JitError {
    #[error("Invalid grant: {0}")]
    InvalidGrant(String),
    
    #[error("Grant expired")]
    GrantExpired,
    
    #[error("Grant not yet valid")]
    GrantNotYetValid,
    
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("JWT error: {0}")]
    Jwt(#[from] jsonwebtoken::errors::Error),
}

pub type Result<T> = std::result::Result<T, JitError>;

/// Execution context for sudo command
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExecContext {
    pub user: String,
    pub runas: String,
    pub command: String,
    pub argv: Vec<String>,
    pub cwd: String,
    pub env: std::collections::HashMap<String, String>,
    pub host_id: String,
    pub timestamp: i64,
}

/// Decision from grant validation
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Decision {
    pub allowed: bool,
    pub reason: String,
    pub grant_id: Option<String>,
    pub ttl_remaining: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exec_context() {
        let ctx = ExecContext {
            user: "alice".to_string(),
            runas: "root".to_string(),
            command: "/bin/systemctl".to_string(),
            argv: vec!["systemctl".to_string(), "restart".to_string(), "nginx".to_string()],
            cwd: "/home/alice".to_string(),
            env: std::collections::HashMap::new(),
            host_id: "host123".to_string(),
            timestamp: 1234567890,
        };
        
        assert_eq!(ctx.user, "alice");
        assert_eq!(ctx.runas, "root");
    }
}
