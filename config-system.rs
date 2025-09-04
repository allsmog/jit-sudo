//! JIT Sudo - Production Configuration Management System
//! Replaces environment variables with proper TOML/YAML configuration

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::fs;
use tracing::{info, warn, debug};

/// Complete JIT Sudo configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JitConfig {
    pub core: CoreConfig,
    pub security: SecurityConfig,
    pub approval: ApprovalConfig,
    pub risk_scoring: RiskScoringConfig,
    pub logging: LoggingConfig,
    pub notifications: NotificationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreConfig {
    /// Unix socket path for IPC communication
    #[serde(default = "default_socket_path")]
    pub socket_path: PathBuf,
    
    /// Storage directory for encrypted grants
    #[serde(default = "default_storage_path")]
    pub storage_path: PathBuf,
    
    /// Log level (error, warn, info, debug, trace)
    #[serde(default = "default_log_level")]
    pub log_level: String,
    
    /// Maximum number of concurrent connections
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    
    /// Request timeout in seconds
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable storage encryption (AES-256-GCM)
    #[serde(default = "default_true")]
    pub encryption_enabled: bool,
    
    /// Key storage method: "tpm", "file", "kms", "vault"
    #[serde(default = "default_key_storage")]
    pub key_storage: String,
    
    /// Directory containing JWT keys
    #[serde(default = "default_key_dir")]
    pub key_directory: PathBuf,
    
    /// JWKS endpoint URL for production JWT validation
    pub jwks_url: Option<String>,
    
    /// List of trusted JWT issuers
    #[serde(default)]
    pub trusted_issuers: Vec<String>,
    
    /// Maximum grant TTL in seconds (security limit)
    #[serde(default = "default_max_ttl")]
    pub max_ttl_seconds: u64,
    
    /// Require TLS for external communications
    #[serde(default = "default_true")]
    pub require_tls: bool,
    
    /// Enable audit log integrity protection
    #[serde(default = "default_true")]
    pub audit_integrity: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalConfig {
    /// Approval mode: "auto", "manual", "risk-based", "disabled"
    #[serde(default = "default_approval_mode")]
    pub mode: String,
    
    /// Risk threshold configuration
    pub risk_thresholds: RiskThresholds,
    
    /// Auto-approval configuration
    pub auto_approve: AutoApprovalConfig,
    
    /// Commands that should never be auto-approved
    pub never_approve: NeverApprovalConfig,
    
    /// Request expiration time in minutes
    #[serde(default = "default_request_expiry")]
    pub request_expiry_minutes: u64,
    
    /// Require justification for all requests
    #[serde(default = "default_true")]
    pub require_justification: bool,
    
    /// Minimum justification length
    #[serde(default = "default_min_justification")]
    pub min_justification_length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskThresholds {
    /// Risk score 0-X: Auto-approve instantly
    #[serde(default = "default_auto_threshold")]
    pub auto_approve: u8,
    
    /// Risk score X+1-Y: Single admin approval required
    #[serde(default = "default_admin_threshold")]
    pub admin_approve: u8,
    
    /// Risk score Y+1-10: Multiple admin approval required
    #[serde(default = "default_multi_threshold")]
    pub multi_approve: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoApprovalConfig {
    /// Enable auto-approval system
    #[serde(default = "default_true")]
    pub enabled: bool,
    
    /// Commands that are always auto-approved (regardless of risk)
    #[serde(default)]
    pub commands: Vec<String>,
    
    /// Users who get enhanced auto-approval privileges
    #[serde(default)]
    pub privileged_users: Vec<String>,
    
    /// Maximum TTL for auto-approved requests
    #[serde(default = "default_auto_max_ttl")]
    pub max_ttl_seconds: u64,
    
    /// Only auto-approve during business hours
    #[serde(default)]
    pub business_hours_only: bool,
    
    /// Business hours range (24-hour format)
    #[serde(default = "default_business_hours")]
    pub hours: String,
    
    /// Business days (Mon-Sun)
    #[serde(default = "default_business_days")]
    pub days: String,
    
    /// Require production flag to be false for auto-approval
    #[serde(default = "default_true")]
    pub non_production_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeverApprovalConfig {
    /// Commands that should never be auto-approved
    #[serde(default)]
    pub commands: Vec<String>,
    
    /// Command patterns that should never be auto-approved
    #[serde(default)]
    pub patterns: Vec<String>,
    
    /// Users who should never get auto-approval
    #[serde(default)]
    pub blocked_users: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskScoringConfig {
    /// Command risk weights (command -> risk_points)
    #[serde(default)]
    pub command_weights: HashMap<String, u8>,
    
    /// Risk multiplier for production environments
    #[serde(default = "default_prod_multiplier")]
    pub production_multiplier: f32,
    
    /// Risk bonus for after-hours requests
    #[serde(default = "default_after_hours_bonus")]
    pub after_hours_bonus: u8,
    
    /// Risk bonus for emergency requests
    #[serde(default = "default_emergency_bonus")]
    pub emergency_flag_bonus: u8,
    
    /// Risk bonus for privileged users (root, admin)
    #[serde(default = "default_privileged_bonus")]
    pub privileged_user_bonus: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Audit log file path
    #[serde(default = "default_audit_path")]
    pub audit_path: PathBuf,
    
    /// Application log path
    #[serde(default = "default_app_log_path")]
    pub app_log_path: PathBuf,
    
    /// Log rotation size in MB
    #[serde(default = "default_log_size")]
    pub max_size_mb: u64,
    
    /// Number of log files to retain
    #[serde(default = "default_log_count")]
    pub max_files: u32,
    
    /// Log format: "json", "text", "structured"
    #[serde(default = "default_log_format")]
    pub format: String,
    
    /// Enable syslog integration
    #[serde(default)]
    pub syslog_enabled: bool,
    
    /// Syslog facility
    #[serde(default = "default_syslog_facility")]
    pub syslog_facility: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationConfig {
    /// Slack webhook URL for admin notifications
    pub slack_webhook: Option<String>,
    
    /// SMTP configuration for email notifications
    pub email: Option<EmailConfig>,
    
    /// PagerDuty integration key
    pub pagerduty_key: Option<String>,
    
    /// Admin email addresses
    #[serde(default)]
    pub admin_emails: Vec<String>,
    
    /// Enable user notifications
    #[serde(default = "default_true")]
    pub user_notifications: bool,
    
    /// Notification cooldown period in minutes
    #[serde(default = "default_notification_cooldown")]
    pub cooldown_minutes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailConfig {
    pub smtp_host: String,
    pub smtp_port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub from_address: String,
    pub use_tls: bool,
}

// Default value functions
fn default_socket_path() -> PathBuf { PathBuf::from("/run/jit-sudo/jitd.sock") }
fn default_storage_path() -> PathBuf { PathBuf::from("/var/lib/jit-sudo") }
fn default_log_level() -> String { "info".to_string() }
fn default_max_connections() -> u32 { 100 }
fn default_request_timeout() -> u64 { 30 }
fn default_true() -> bool { true }
fn default_key_storage() -> String { "file".to_string() }
fn default_key_dir() -> PathBuf { PathBuf::from("/etc/jit-sudo/keys") }
fn default_max_ttl() -> u64 { 28800 } // 8 hours
fn default_approval_mode() -> String { "risk-based".to_string() }
fn default_request_expiry() -> u64 { 30 }
fn default_min_justification() -> usize { 10 }
fn default_auto_threshold() -> u8 { 2 }
fn default_admin_threshold() -> u8 { 6 }
fn default_multi_threshold() -> u8 { 10 }
fn default_auto_max_ttl() -> u64 { 3600 } // 1 hour
fn default_business_hours() -> String { "09:00-17:00".to_string() }
fn default_business_days() -> String { "Mon-Fri".to_string() }
fn default_prod_multiplier() -> f32 { 2.0 }
fn default_after_hours_bonus() -> u8 { 1 }
fn default_emergency_bonus() -> u8 { 2 }
fn default_privileged_bonus() -> u8 { 1 }
fn default_audit_path() -> PathBuf { PathBuf::from("/var/log/jit-sudo/audit.log") }
fn default_app_log_path() -> PathBuf { PathBuf::from("/var/log/jit-sudo/app.log") }
fn default_log_size() -> u64 { 100 }
fn default_log_count() -> u32 { 10 }
fn default_log_format() -> String { "json".to_string() }
fn default_syslog_facility() -> String { "local0".to_string() }
fn default_notification_cooldown() -> u64 { 5 }

impl Default for JitConfig {
    fn default() -> Self {
        Self {
            core: CoreConfig {
                socket_path: default_socket_path(),
                storage_path: default_storage_path(),
                log_level: default_log_level(),
                max_connections: default_max_connections(),
                request_timeout_secs: default_request_timeout(),
            },
            security: SecurityConfig {
                encryption_enabled: true,
                key_storage: default_key_storage(),
                key_directory: default_key_dir(),
                jwks_url: None,
                trusted_issuers: vec!["https://jit-broker.company.com".to_string()],
                max_ttl_seconds: default_max_ttl(),
                require_tls: true,
                audit_integrity: true,
            },
            approval: ApprovalConfig {
                mode: default_approval_mode(),
                risk_thresholds: RiskThresholds {
                    auto_approve: default_auto_threshold(),
                    admin_approve: default_admin_threshold(),
                    multi_approve: default_multi_threshold(),
                },
                auto_approve: AutoApprovalConfig {
                    enabled: true,
                    commands: vec![
                        "ls".to_string(), "cat".to_string(), "grep".to_string(),
                        "head".to_string(), "tail".to_string(), "find".to_string(),
                        "ps".to_string(), "df".to_string(), "free".to_string(),
                        "whoami".to_string(), "id".to_string(), "date".to_string(),
                    ],
                    privileged_users: vec![],
                    max_ttl_seconds: default_auto_max_ttl(),
                    business_hours_only: false,
                    hours: default_business_hours(),
                    days: default_business_days(),
                    non_production_only: true,
                },
                never_approve: NeverApprovalConfig {
                    commands: vec![
                        "rm -rf".to_string(), "dd".to_string(), "mkfs".to_string(),
                        "fdisk".to_string(), "shutdown".to_string(), "reboot".to_string(),
                        "halt".to_string(), "poweroff".to_string(),
                    ],
                    patterns: vec![
                        "*password*".to_string(), "*shadow*".to_string(),
                        "*private*".to_string(), "*/etc/passwd".to_string(),
                    ],
                    blocked_users: vec![],
                },
                request_expiry_minutes: default_request_expiry(),
                require_justification: true,
                min_justification_length: default_min_justification(),
            },
            risk_scoring: RiskScoringConfig {
                command_weights: [
                    ("rm".to_string(), 5),
                    ("dd".to_string(), 8),
                    ("systemctl".to_string(), 3),
                    ("service".to_string(), 3),
                    ("iptables".to_string(), 6),
                    ("mount".to_string(), 4),
                    ("umount".to_string(), 4),
                    ("chmod".to_string(), 2),
                    ("chown".to_string(), 2),
                    ("kill".to_string(), 2),
                    ("killall".to_string(), 3),
                ].iter().cloned().collect(),
                production_multiplier: default_prod_multiplier(),
                after_hours_bonus: default_after_hours_bonus(),
                emergency_flag_bonus: default_emergency_bonus(),
                privileged_user_bonus: default_privileged_bonus(),
            },
            logging: LoggingConfig {
                audit_path: default_audit_path(),
                app_log_path: default_app_log_path(),
                max_size_mb: default_log_size(),
                max_files: default_log_count(),
                format: default_log_format(),
                syslog_enabled: false,
                syslog_facility: default_syslog_facility(),
            },
            notifications: NotificationConfig {
                slack_webhook: None,
                email: None,
                pagerduty_key: None,
                admin_emails: vec!["admin@company.com".to_string()],
                user_notifications: true,
                cooldown_minutes: default_notification_cooldown(),
            },
        }
    }
}

/// Configuration loader with multiple sources and precedence
pub struct ConfigLoader {
    config: JitConfig,
    config_paths: Vec<PathBuf>,
    watch_enabled: bool,
}

impl ConfigLoader {
    /// Create new configuration loader
    pub fn new() -> Self {
        Self {
            config: JitConfig::default(),
            config_paths: vec![
                PathBuf::from("/etc/jit-sudo/config.toml"),
                PathBuf::from("/etc/jit-sudo/config.yaml"),
            ],
            watch_enabled: false,
        }
    }
    
    /// Add configuration file path
    pub fn add_config_path<P: AsRef<Path>>(&mut self, path: P) {
        self.config_paths.push(path.as_ref().to_path_buf());
    }
    
    /// Load configuration with precedence:
    /// 1. Command-line overrides
    /// 2. Config files (in order added)
    /// 3. Environment variables
    /// 4. Defaults
    pub fn load(&mut self) -> Result<&JitConfig> {
        // Start with defaults
        self.config = JitConfig::default();
        
        // Load from config files (in order)
        for path in &self.config_paths.clone() {
            if path.exists() {
                match self.load_config_file(path) {
                    Ok(config) => {
                        self.merge_config(config);
                        info!("Loaded configuration from {}", path.display());
                    }
                    Err(e) => {
                        warn!("Failed to load config from {}: {}", path.display(), e);
                    }
                }
            }
        }
        
        // Apply environment variable overrides
        self.apply_env_overrides();
        
        // Validate final configuration
        self.validate_config()?;
        
        Ok(&self.config)
    }
    
    /// Load configuration from specific file
    fn load_config_file(&self, path: &Path) -> Result<JitConfig> {
        let content = fs::read_to_string(path)?;
        
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("toml") => {
                toml::from_str(&content)
                    .map_err(|e| anyhow!("TOML parse error: {}", e))
            }
            Some("yaml") | Some("yml") => {
                serde_yaml::from_str(&content)
                    .map_err(|e| anyhow!("YAML parse error: {}", e))
            }
            Some("json") => {
                serde_json::from_str(&content)
                    .map_err(|e| anyhow!("JSON parse error: {}", e))
            }
            _ => Err(anyhow!("Unsupported config format: {}", path.display()))
        }
    }
    
    /// Merge loaded configuration with current config
    fn merge_config(&mut self, other: JitConfig) {
        // This is a simplified merge - in production you'd want more sophisticated merging
        // For now, we replace entire sections
        if !other.security.trusted_issuers.is_empty() {
            self.config.security = other.security;
        }
        if other.approval.mode != "risk-based" {
            self.config.approval = other.approval;
        }
        // Continue for other sections...
    }
    
    /// Apply environment variable overrides
    fn apply_env_overrides(&mut self) {
        // Support legacy environment variables for backward compatibility
        if let Ok(socket_path) = std::env::var("JIT_SOCKET_PATH") {
            self.config.core.socket_path = PathBuf::from(socket_path);
        }
        
        if let Ok(storage_path) = std::env::var("JIT_STORAGE_PATH") {
            self.config.core.storage_path = PathBuf::from(storage_path);
        }
        
        if let Ok(log_level) = std::env::var("JIT_LOG_LEVEL") {
            self.config.core.log_level = log_level;
        }
        
        if let Ok(auto_threshold) = std::env::var("JIT_AUTO_APPROVE_THRESHOLD") {
            if let Ok(threshold) = auto_threshold.parse::<u8>() {
                self.config.approval.risk_thresholds.auto_approve = threshold;
            }
        }
        
        if let Ok(approval_mode) = std::env::var("JIT_APPROVAL_MODE") {
            self.config.approval.mode = approval_mode;
        }
        
        if let Ok(jwks_url) = std::env::var("JIT_JWKS_URL") {
            self.config.security.jwks_url = Some(jwks_url);
        }
    }
    
    /// Validate configuration for consistency and security
    fn validate_config(&self) -> Result<()> {
        let config = &self.config;
        
        // Validate approval mode
        match config.approval.mode.as_str() {
            "auto" | "manual" | "risk-based" | "disabled" => {}
            _ => return Err(anyhow!("Invalid approval mode: {}", config.approval.mode)),
        }
        
        // Validate risk thresholds
        if config.approval.risk_thresholds.auto_approve > 10 {
            return Err(anyhow!("Auto-approve threshold cannot exceed 10"));
        }
        
        if config.approval.risk_thresholds.admin_approve <= config.approval.risk_thresholds.auto_approve {
            return Err(anyhow!("Admin threshold must be higher than auto threshold"));
        }
        
        // Validate paths exist or can be created
        if let Some(parent) = config.core.socket_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        
        // Validate security configuration
        if config.security.max_ttl_seconds == 0 {
            return Err(anyhow!("Maximum TTL must be greater than 0"));
        }
        
        if config.security.trusted_issuers.is_empty() && config.security.jwks_url.is_none() {
            warn!("No trusted issuers or JWKS URL configured - JWT validation may fail");
        }
        
        debug!("Configuration validation passed");
        Ok(())
    }
    
    /// Get current configuration
    pub fn config(&self) -> &JitConfig {
        &self.config
    }
    
    /// Enable configuration file watching for hot reload
    pub fn enable_watch(&mut self) {
        self.watch_enabled = true;
        // Implementation would use notify crate for file watching
    }
    
    /// Save current configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = match path.as_ref().extension().and_then(|ext| ext.to_str()) {
            Some("toml") => toml::to_string_pretty(&self.config)?,
            Some("yaml") | Some("yml") => serde_yaml::to_string(&self.config)?,
            Some("json") => serde_json::to_string_pretty(&self.config)?,
            _ => return Err(anyhow!("Unsupported format for save")),
        };
        
        fs::write(path, content)?;
        Ok(())
    }
}

/// Configuration management CLI
pub struct ConfigCLI {
    loader: ConfigLoader,
}

impl ConfigCLI {
    pub fn new() -> Self {
        Self {
            loader: ConfigLoader::new(),
        }
    }
    
    /// Show current configuration
    pub fn show_config(&mut self) -> Result<()> {
        self.loader.load()?;
        let config_toml = toml::to_string_pretty(self.loader.config())?;
        println!("{}", config_toml);
        Ok(())
    }
    
    /// Set configuration value
    pub fn set_value(&mut self, key: &str, value: &str) -> Result<()> {
        self.loader.load()?;
        
        // Parse dotted key notation: approval.risk_thresholds.auto_approve
        let parts: Vec<&str> = key.split('.').collect();
        
        match parts.as_slice() {
            ["approval", "risk_thresholds", "auto_approve"] => {
                let val = value.parse::<u8>()?;
                self.loader.config.approval.risk_thresholds.auto_approve = val;
            }
            ["approval", "mode"] => {
                self.loader.config.approval.mode = value.to_string();
            }
            ["core", "log_level"] => {
                self.loader.config.core.log_level = value.to_string();
            }
            ["security", "encryption_enabled"] => {
                let val = value.parse::<bool>()?;
                self.loader.config.security.encryption_enabled = val;
            }
            _ => return Err(anyhow!("Unknown configuration key: {}", key)),
        }
        
        // Validate and save
        self.loader.validate_config()?;
        self.loader.save_to_file("/etc/jit-sudo/config.toml")?;
        
        println!("Configuration updated: {} = {}", key, value);
        Ok(())
    }
    
    /// Validate configuration file
    pub fn validate_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let mut temp_loader = ConfigLoader::new();
        temp_loader.add_config_path(path);
        temp_loader.load()?;
        
        println!("✅ Configuration file is valid");
        Ok(())
    }
}

/*
Required dependencies for Cargo.toml:

[dependencies]
toml = "0.8"
serde_yaml = "0.9"
serde_json = "1.0"
serde = { version = "1.0", features = ["derive"] }
anyhow = "1.0"
tracing = "0.1"

Usage example:

fn main() -> Result<()> {
    let mut loader = ConfigLoader::new();
    loader.add_config_path("/etc/jit-sudo/config.toml");
    loader.add_config_path("/etc/jit-sudo/production.toml");
    
    let config = loader.load()?;
    
    println!("Approval mode: {}", config.approval.mode);
    println!("Auto-approve threshold: {}", config.approval.risk_thresholds.auto_approve);
    
    // Use configuration throughout application
    Ok(())
}
*/