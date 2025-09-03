//! JWT Grant verification and management

use crate::{ExecContext, JitError, Result};
use chrono::Utc;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// JIT Grant structure (JWT claims)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitGrant {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub jti: String,
    pub nbf: i64,
    pub exp: i64,
    pub claimset: GrantClaims,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantClaims {
    pub host_fingerprint: String,
    pub run_as: String,
    pub cmnd_patterns: Vec<String>,
    pub env_whitelist: Vec<String>,
    pub max_tty_timeout: i64,
    pub approvals: Vec<Approval>,
    pub ticket: String,
    pub risk: RiskContext,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub by: String,
    pub method: String,
    pub ts: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskContext {
    pub change_ref: Option<String>,
    pub prod: bool,
}

#[derive(Clone)]
pub struct GrantVerifier {
    trusted_issuers: HashSet<String>,
}

impl GrantVerifier {
    pub fn new(trusted_issuers: Vec<String>) -> Self {
        Self {
            trusted_issuers: trusted_issuers.into_iter().collect(),
        }
    }
    
    pub fn verify_grant(&self, token: &str) -> Result<JitGrant> {
        let key = DecodingKey::from_secret(b"dev-secret-key");
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_audience(&["jit-sudo/v1"]);
        
        let token_data = decode::<JitGrant>(token, &key, &validation)?;
        let grant = token_data.claims;
        
        if !self.trusted_issuers.contains(&grant.iss) {
            return Err(JitError::InvalidGrant(format!("Untrusted issuer: {}", grant.iss)));
        }
        
        let now = Utc::now().timestamp();
        if grant.exp < now {
            return Err(JitError::GrantExpired);
        }
        
        Ok(grant)
    }
    
    pub fn matches_context(&self, grant: &JitGrant, ctx: &ExecContext) -> bool {
        if grant.sub != ctx.user {
            return false;
        }
        
        if grant.claimset.run_as != "*" && grant.claimset.run_as != ctx.runas {
            return false;
        }
        
        let full_command = format!("{} {}", ctx.command, ctx.argv.join(" "));
        grant.claimset.cmnd_patterns.iter().any(|pattern| {
            if pattern.ends_with('*') {
                let prefix = &pattern[..pattern.len() - 1];
                full_command.starts_with(prefix)
            } else {
                full_command == *pattern
            }
        })
    }
}
