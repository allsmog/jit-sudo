// JIT Sudo - Production JWT Security Implementation
// This demonstrates how to replace hardcoded secrets with proper key management

use std::fs;
use std::env;
use std::path::Path;
use jsonwebtoken::{DecodingKey, EncodingKey, Algorithm};
use anyhow::{Result, anyhow};

/// Production-ready JWT key management
pub struct JwtKeyManager {
    private_key: Option<EncodingKey>,
    public_key: DecodingKey,
    algorithm: Algorithm,
}

impl JwtKeyManager {
    /// Initialize from production key files
    pub fn new() -> Result<Self> {
        let key_dir = env::var("JIT_SUDO_KEY_DIR")
            .unwrap_or_else(|_| "/etc/jit-sudo/keys".to_string());
            
        let private_key_path = Path::new(&key_dir).join("private.pem");
        let public_key_path = Path::new(&key_dir).join("public.pem");
        
        // Load public key (required for verification)
        let public_pem = fs::read(&public_key_path)
            .map_err(|e| anyhow!("Failed to read public key from {}: {}", 
                                 public_key_path.display(), e))?;
        
        let public_key = DecodingKey::from_ec_pem(&public_pem)
            .map_err(|e| anyhow!("Invalid public key format: {}", e))?;
        
        // Load private key (optional - only for signing)
        let private_key = if private_key_path.exists() {
            let private_pem = fs::read(&private_key_path)
                .map_err(|e| anyhow!("Failed to read private key from {}: {}", 
                                     private_key_path.display(), e))?;
            
            Some(EncodingKey::from_ec_pem(&private_pem)
                .map_err(|e| anyhow!("Invalid private key format: {}", e))?)
        } else {
            None
        };
        
        Ok(Self {
            private_key,
            public_key,
            algorithm: Algorithm::ES256, // ECDSA with SHA-256
        })
    }
    
    /// Create from JWKS endpoint (production deployment)
    pub async fn from_jwks(jwks_url: &str) -> Result<Self> {
        // In production, fetch from JWKS endpoint
        let response = reqwest::get(jwks_url).await?;
        let jwks: serde_json::Value = response.json().await?;
        
        // Extract first key (simplified - should handle key selection)
        let key = jwks["keys"][0].clone();
        
        // Convert JWKS to DecodingKey
        let public_key = DecodingKey::from_jwk(&key)?;
        
        Ok(Self {
            private_key: None, // No signing in verification-only mode
            public_key,
            algorithm: Algorithm::RS256, // RSA with SHA-256 for JWKS
        })
    }
    
    /// Verify JWT token (replaces hardcoded secret)
    pub fn verify_token(&self, token: &str) -> Result<jsonwebtoken::TokenData<crate::JitGrant>> {
        use jsonwebtoken::{decode, Validation};
        
        let mut validation = Validation::new(self.algorithm);
        validation.set_audience(&["jit-sudo/v1"]);
        validation.set_issuer(&["https://jit-broker.company.com"]); // Production issuer
        
        // This replaces the hardcoded b"dev-secret-key"
        decode::<crate::JitGrant>(token, &self.public_key, &validation)
            .map_err(|e| anyhow!("JWT verification failed: {}", e))
    }
    
    /// Sign JWT token (for testing/development broker)
    pub fn sign_token(&self, claims: &crate::JitGrant) -> Result<String> {
        let private_key = self.private_key.as_ref()
            .ok_or_else(|| anyhow!("No private key available for signing"))?;
        
        use jsonwebtoken::{encode, Header};
        
        let header = Header::new(self.algorithm);
        encode(&header, claims, private_key)
            .map_err(|e| anyhow!("JWT signing failed: {}", e))
    }
}

/// Production key generation utility
pub fn generate_production_keys(output_dir: &str) -> Result<()> {
    use openssl::ec::{EcGroup, EcKey};
    use openssl::nid::Nid;
    use openssl::pkey::PKey;
    
    println!("Generating production ECDSA key pair...");
    
    // Generate P-256 curve key pair
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let ec_key = EcKey::generate(&group)?;
    let pkey = PKey::from_ec_key(ec_key)?;
    
    // Create output directory
    std::fs::create_dir_all(output_dir)?;
    
    // Write private key
    let private_pem = pkey.private_key_to_pem_pkcs8()?;
    let private_path = Path::new(output_dir).join("private.pem");
    fs::write(&private_path, private_pem)?;
    
    // Set restrictive permissions on private key
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&private_path)?.permissions();
        perms.set_mode(0o600); // Read/write for owner only
        fs::set_permissions(&private_path, perms)?;
    }
    
    // Write public key
    let public_pem = pkey.public_key_to_pem()?;
    let public_path = Path::new(output_dir).join("public.pem");
    fs::write(&public_path, public_pem)?;
    
    println!("✅ Keys generated successfully:");
    println!("   Private: {}", private_path.display());
    println!("   Public:  {}", public_path.display());
    println!("\nIMPORTANT: Secure the private key immediately!");
    println!("   sudo chown root:root {}", private_path.display());
    println!("   sudo chmod 600 {}", private_path.display());
    
    Ok(())
}

/// Environment-based configuration
pub struct SecurityConfig {
    pub jwt_key_dir: String,
    pub jwks_url: Option<String>,
    pub trusted_issuers: Vec<String>,
    pub require_mfa: bool,
    pub max_ttl_seconds: u64,
}

impl SecurityConfig {
    pub fn from_environment() -> Self {
        Self {
            jwt_key_dir: env::var("JIT_SUDO_KEY_DIR")
                .unwrap_or_else(|_| "/etc/jit-sudo/keys".to_string()),
            jwks_url: env::var("JIT_SUDO_JWKS_URL").ok(),
            trusted_issuers: env::var("JIT_SUDO_TRUSTED_ISSUERS")
                .unwrap_or_else(|_| "https://jit-broker.company.com".to_string())
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
            require_mfa: env::var("JIT_SUDO_REQUIRE_MFA")
                .map(|v| v == "true")
                .unwrap_or(false),
            max_ttl_seconds: env::var("JIT_SUDO_MAX_TTL")
                .and_then(|v| v.parse().ok())
                .unwrap_or(3600), // 1 hour default
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_generation() {
        let temp_dir = tempfile::tempdir().unwrap();
        generate_production_keys(temp_dir.path().to_str().unwrap()).unwrap();
        
        assert!(temp_dir.path().join("private.pem").exists());
        assert!(temp_dir.path().join("public.pem").exists());
    }
    
    #[test]
    fn test_jwt_round_trip() {
        use crate::{JitGrant, GrantClaims};
        use chrono::Utc;
        
        let temp_dir = tempfile::tempdir().unwrap();
        generate_production_keys(temp_dir.path().to_str().unwrap()).unwrap();
        
        std::env::set_var("JIT_SUDO_KEY_DIR", temp_dir.path());
        
        let key_manager = JwtKeyManager::new().unwrap();
        
        let grant = JitGrant {
            iss: "https://test.com".to_string(),
            sub: "testuser".to_string(),
            aud: "jit-sudo/v1".to_string(),
            jti: "test-grant-123".to_string(),
            nbf: Utc::now().timestamp(),
            exp: Utc::now().timestamp() + 3600,
            claimset: GrantClaims {
                host_fingerprint: "test-host".to_string(),
                run_as: "root".to_string(),
                cmnd_patterns: vec!["systemctl restart nginx".to_string()],
                env_whitelist: vec![],
                max_tty_timeout: 300,
                approvals: vec![],
                ticket: "TEST-123".to_string(),
                risk: crate::RiskContext {
                    change_ref: None,
                    prod: false,
                },
            },
        };
        
        // Sign and verify
        let token = key_manager.sign_token(&grant).unwrap();
        let verified = key_manager.verify_token(&token).unwrap();
        
        assert_eq!(verified.claims.sub, "testuser");
        assert_eq!(verified.claims.jti, "test-grant-123");
    }
}

// Usage example for production deployment:
/*
fn main() -> Result<()> {
    // Generate keys once during setup
    generate_production_keys("/etc/jit-sudo/keys")?;
    
    // Initialize key manager
    let config = SecurityConfig::from_environment();
    std::env::set_var("JIT_SUDO_KEY_DIR", config.jwt_key_dir);
    
    let key_manager = JwtKeyManager::new()?;
    
    // Use in place of hardcoded secret:
    // OLD: let key = DecodingKey::from_secret(b"dev-secret-key");
    // NEW: let verified = key_manager.verify_token(&token)?;
    
    Ok(())
}
*/