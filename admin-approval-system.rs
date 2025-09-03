// JIT Sudo - Admin Approval Workflow System
// This implements proper human approval instead of auto-granting access

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use tracing::{info, warn, error};

/// Pending access request awaiting approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRequest {
    pub id: String,
    pub user: String,
    pub command: String,
    pub justification: String,
    pub requested_ttl: u64,
    pub risk_score: u8,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: RequestStatus,
    pub approver: Option<String>,
    pub approval_comment: Option<String>,
    pub approval_at: Option<DateTime<Utc>>,
    pub metadata: RequestMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RequestStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestMetadata {
    pub host_fingerprint: String,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub ticket_ref: Option<String>,
    pub emergency: bool,
    pub production_impact: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalDecision {
    pub request_id: String,
    pub decision: RequestStatus,
    pub approver: String,
    pub comment: Option<String>,
    pub override_ttl: Option<u64>,
    pub conditions: Vec<String>,
}

/// Risk assessment for access requests
#[derive(Debug, Clone)]
pub struct RiskAssessment {
    pub score: u8,        // 0-10
    pub factors: Vec<String>,
    pub auto_approve: bool,
    pub require_multiple_approvers: bool,
}

/// Admin approval workflow manager
pub struct ApprovalWorkflow {
    storage: Box<dyn ApprovalStorage>,
    risk_assessor: RiskAssessor,
    notification_service: NotificationService,
    policies: ApprovalPolicies,
}

impl ApprovalWorkflow {
    pub fn new(storage: Box<dyn ApprovalStorage>) -> Self {
        Self {
            storage,
            risk_assessor: RiskAssessor::new(),
            notification_service: NotificationService::new(),
            policies: ApprovalPolicies::default(),
        }
    }
    
    /// Submit new access request (replaces auto-approval)
    pub async fn submit_request(
        &self,
        user: &str,
        command: &str,
        justification: &str,
        requested_ttl: u64,
        metadata: RequestMetadata,
    ) -> Result<String> {
        
        // Validate input
        if justification.trim().len() < 10 {
            return Err(anyhow!("Justification must be at least 10 characters"));
        }
        
        // Assess risk
        let risk = self.risk_assessor.assess_risk(user, command, &metadata)?;
        
        // Create request
        let request_id = format!("req-{}", Uuid::new_v4());
        let now = Utc::now();
        
        let request = PendingRequest {
            id: request_id.clone(),
            user: user.to_string(),
            command: command.to_string(),
            justification: justification.to_string(),
            requested_ttl,
            risk_score: risk.score,
            requested_at: now,
            expires_at: now + chrono::Duration::minutes(30), // Request expires in 30 min
            status: RequestStatus::Pending,
            approver: None,
            approval_comment: None,
            approval_at: None,
            metadata,
        };
        
        // Store request
        self.storage.store_request(&request).await?;
        
        // Handle based on risk level
        if risk.auto_approve && !request.metadata.production_impact {
            // Auto-approve low-risk requests
            self.auto_approve(&request_id, "System auto-approval").await?;
            info!("Auto-approved low-risk request: {}", request_id);
        } else {
            // Require human approval
            self.notify_admins(&request).await?;
            info!("Request {} submitted for approval (risk: {})", request_id, risk.score);
        }
        
        Ok(request_id)
    }
    
    /// Approve pending request
    pub async fn approve_request(&self, decision: ApprovalDecision) -> Result<String> {
        let mut request = self.storage.load_request(&decision.request_id).await?
            .ok_or_else(|| anyhow!("Request not found: {}", decision.request_id))?;
        
        // Validate request state
        if request.status != RequestStatus::Pending {
            return Err(anyhow!("Request {} is not pending (status: {:?})", 
                              decision.request_id, request.status));
        }
        
        if Utc::now() > request.expires_at {
            request.status = RequestStatus::Expired;
            self.storage.store_request(&request).await?;
            return Err(anyhow!("Request {} has expired", decision.request_id));
        }
        
        // Update request with approval
        request.status = decision.decision.clone();
        request.approver = Some(decision.approver.clone());
        request.approval_comment = decision.comment.clone();
        request.approval_at = Some(Utc::now());
        
        self.storage.store_request(&request).await?;
        
        match decision.decision {
            RequestStatus::Approved => {
                // Generate JWT token through proper broker
                let ttl = decision.override_ttl.unwrap_or(request.requested_ttl);
                let token = self.create_approved_token(&request, ttl, &decision.conditions).await?;
                
                // Install grant in jitd
                self.install_approved_grant(&token).await?;
                
                // Notify user
                self.notification_service.notify_user_approved(&request).await?;
                
                info!("Request {} approved by {} for {} seconds", 
                      decision.request_id, decision.approver, ttl);
                      
                Ok(token)
            },
            RequestStatus::Denied => {
                // Notify user of denial
                self.notification_service.notify_user_denied(&request, &decision).await?;
                
                info!("Request {} denied by {}: {}", 
                      decision.request_id, decision.approver, 
                      decision.comment.as_deref().unwrap_or("No reason provided"));
                      
                Err(anyhow!("Request denied: {}", 
                           decision.comment.as_deref().unwrap_or("No reason provided")))
            },
            _ => Err(anyhow!("Invalid approval decision"))
        }
    }
    
    /// List pending requests for admin review
    pub async fn list_pending_requests(&self, admin_user: &str) -> Result<Vec<PendingRequest>> {
        let requests = self.storage.list_requests_by_status(RequestStatus::Pending).await?;
        
        // Filter based on admin permissions
        let filtered_requests: Vec<PendingRequest> = requests.into_iter()
            .filter(|req| self.policies.can_approve(admin_user, req))
            .collect();
            
        Ok(filtered_requests)
    }
    
    /// Emergency break-glass approval (requires post-incident review)
    pub async fn emergency_approve(
        &self,
        request_id: &str,
        approver: &str,
        incident_ticket: &str,
    ) -> Result<String> {
        let mut request = self.storage.load_request(request_id).await?
            .ok_or_else(|| anyhow!("Request not found: {}", request_id))?;
        
        warn!("EMERGENCY APPROVAL: {} by {} for incident {}", 
              request_id, approver, incident_ticket);
        
        // Force approval with extended TTL
        request.status = RequestStatus::Approved;
        request.approver = Some(format!("EMERGENCY:{}", approver));
        request.approval_comment = Some(format!("Emergency approval for incident: {}", incident_ticket));
        request.approval_at = Some(Utc::now());
        
        self.storage.store_request(&request).await?;
        
        // Create emergency grant (4 hour max)
        let emergency_ttl = std::cmp::min(request.requested_ttl, 14400); // 4 hours max
        let token = self.create_approved_token(&request, emergency_ttl, &vec!["EMERGENCY".to_string()]).await?;
        
        // Install and notify security team
        self.install_approved_grant(&token).await?;
        self.notification_service.notify_emergency_approval(&request, incident_ticket).await?;
        
        Ok(token)
    }
    
    /// Auto-approve low-risk requests
    async fn auto_approve(&self, request_id: &str, reason: &str) -> Result<()> {
        let decision = ApprovalDecision {
            request_id: request_id.to_string(),
            decision: RequestStatus::Approved,
            approver: "system".to_string(),
            comment: Some(reason.to_string()),
            override_ttl: None,
            conditions: vec!["auto-approved".to_string()],
        };
        
        self.approve_request(decision).await?;
        Ok(())
    }
    
    /// Create JWT token for approved request
    async fn create_approved_token(
        &self,
        request: &PendingRequest,
        ttl: u64,
        conditions: &[String],
    ) -> Result<String> {
        // This would integrate with the JWT broker system
        // Instead of local mock token generation
        
        use libjit_sudo::grant::*;
        use jsonwebtoken::{encode, Header, EncodingKey};
        
        let now = Utc::now().timestamp();
        let grant = JitGrant {
            iss: "https://jit-broker.company.com".to_string(),
            sub: request.user.clone(),
            aud: "jit-sudo/v1".to_string(),
            jti: format!("approved-{}", request.id),
            nbf: now,
            exp: now + ttl as i64,
            claimset: GrantClaims {
                host_fingerprint: request.metadata.host_fingerprint.clone(),
                run_as: "root".to_string(),
                cmnd_patterns: vec![request.command.clone()],
                env_whitelist: vec![],
                max_tty_timeout: 300,
                approvals: vec![Approval {
                    by: request.approver.as_ref().unwrap_or(&"system".to_string()).clone(),
                    method: "jit-workflow".to_string(),
                    ts: request.approval_at.unwrap_or(Utc::now()).to_rfc3339(),
                }],
                ticket: request.metadata.ticket_ref.clone().unwrap_or_default(),
                risk: RiskContext {
                    change_ref: request.metadata.ticket_ref.clone(),
                    prod: request.metadata.production_impact,
                },
            },
        };
        
        // In production, this would use proper key management
        // For now, demonstrate the structure
        let header = Header::new(jsonwebtoken::Algorithm::RS256);
        let key = EncodingKey::from_rsa_pem(include_bytes!("/etc/jit-sudo/keys/private.pem"))
            .map_err(|e| anyhow!("Failed to load signing key: {}", e))?;
            
        let token = encode(&header, &grant, &key)?;
        Ok(token)
    }
    
    /// Install approved grant in jitd
    async fn install_approved_grant(&self, token: &str) -> Result<()> {
        // Connect to jitd and install the grant
        use crate::ipc::{IpcClient, IpcRequest};
        
        let client = IpcClient::new("/run/jit-sudo/jitd.sock");
        client.send_request(IpcRequest::InstallGrant { 
            token: token.to_string() 
        }).await?;
        
        Ok(())
    }
    
    /// Notify admins of new request
    async fn notify_admins(&self, request: &PendingRequest) -> Result<()> {
        self.notification_service.send_admin_notification(request).await
    }
}

/// Risk assessment engine
pub struct RiskAssessor {
    high_risk_commands: Vec<String>,
    production_patterns: Vec<String>,
}

impl RiskAssessor {
    pub fn new() -> Self {
        Self {
            high_risk_commands: vec![
                "rm".to_string(),
                "dd".to_string(),
                "mkfs".to_string(),
                "fdisk".to_string(),
                "systemctl stop".to_string(),
                "iptables".to_string(),
                "ufw".to_string(),
            ],
            production_patterns: vec![
                "prod".to_string(),
                "production".to_string(),
                "database".to_string(),
                "mysql".to_string(),
                "postgresql".to_string(),
            ],
        }
    }
    
    pub fn assess_risk(&self, user: &str, command: &str, metadata: &RequestMetadata) -> Result<RiskAssessment> {
        let mut score = 1u8; // Base risk
        let mut factors = Vec::new();
        
        // Command risk
        for high_risk_cmd in &self.high_risk_commands {
            if command.contains(high_risk_cmd) {
                score += 3;
                factors.push(format!("high-risk-command: {}", high_risk_cmd));
            }
        }
        
        // Production environment
        if metadata.production_impact {
            score += 2;
            factors.push("production-environment".to_string());
        }
        
        for pattern in &self.production_patterns {
            if command.to_lowercase().contains(pattern) {
                score += 1;
                factors.push(format!("production-pattern: {}", pattern));
            }
        }
        
        // Time-based risk (after hours)
        let hour = Utc::now().hour();
        if hour < 8 || hour > 18 { // Outside business hours
            score += 1;
            factors.push("after-hours".to_string());
        }
        
        // Emergency flag
        if metadata.emergency {
            score += 2;
            factors.push("emergency-request".to_string());
        }
        
        // User risk (simplified - would integrate with identity provider)
        if user.contains("admin") || user.contains("root") {
            score += 1;
            factors.push("privileged-user".to_string());
        }
        
        score = std::cmp::min(score, 10); // Cap at 10
        
        Ok(RiskAssessment {
            score,
            factors,
            auto_approve: score <= 2,
            require_multiple_approvers: score >= 7,
        })
    }
}

/// Approval policies and permissions
#[derive(Clone)]
pub struct ApprovalPolicies {
    admin_users: Vec<String>,
    department_approvers: HashMap<String, Vec<String>>,
}

impl Default for ApprovalPolicies {
    fn default() -> Self {
        Self {
            admin_users: vec!["admin".to_string(), "security".to_string()],
            department_approvers: HashMap::new(),
        }
    }
}

impl ApprovalPolicies {
    pub fn can_approve(&self, admin_user: &str, request: &PendingRequest) -> bool {
        // Global admins can approve everything
        if self.admin_users.contains(&admin_user.to_string()) {
            return true;
        }
        
        // Department-specific approvals (simplified)
        if let Some(approvers) = self.department_approvers.get(&request.user) {
            return approvers.contains(&admin_user.to_string());
        }
        
        false
    }
}

/// Notification service for admins and users
pub struct NotificationService;

impl NotificationService {
    pub fn new() -> Self {
        Self
    }
    
    pub async fn send_admin_notification(&self, request: &PendingRequest) -> Result<()> {
        let message = format!(
            "🔐 JIT Access Request\n\
             User: {}\n\
             Command: {}\n\
             Risk: {} ({})\n\
             Justification: {}\n\
             Expires: {}\n\
             \n\
             Approve: jitctl admin approve {}\n\
             Deny: jitctl admin deny {}",
            request.user,
            request.command,
            request.risk_score,
            if request.risk_score >= 7 { "HIGH" } 
            else if request.risk_score >= 4 { "MEDIUM" } 
            else { "LOW" },
            request.justification,
            request.expires_at.format("%Y-%m-%d %H:%M UTC"),
            request.id,
            request.id
        );
        
        // Send to Slack, email, etc.
        self.send_slack_message("#jit-sudo-approvals", &message).await?;
        self.send_email("jit-admins@company.com", "JIT Access Request", &message).await?;
        
        Ok(())
    }
    
    pub async fn notify_user_approved(&self, request: &PendingRequest) -> Result<()> {
        let message = format!("✅ Your JIT access request has been approved!\nRequest ID: {}\nCommand: {}\nApprover: {}", 
                             request.id, request.command, 
                             request.approver.as_deref().unwrap_or("system"));
        
        // Send user notification
        self.send_user_notification(&request.user, &message).await
    }
    
    pub async fn notify_user_denied(&self, request: &PendingRequest, decision: &ApprovalDecision) -> Result<()> {
        let message = format!("❌ Your JIT access request has been denied.\nRequest ID: {}\nReason: {}", 
                             request.id, 
                             decision.comment.as_deref().unwrap_or("No reason provided"));
        
        self.send_user_notification(&request.user, &message).await
    }
    
    pub async fn notify_emergency_approval(&self, request: &PendingRequest, incident: &str) -> Result<()> {
        let message = format!("🚨 EMERGENCY JIT APPROVAL\nUser: {}\nCommand: {}\nIncident: {}\nApprover: {}",
                             request.user, request.command, incident,
                             request.approver.as_deref().unwrap_or("unknown"));
        
        // Alert security team
        self.send_slack_message("#security-alerts", &message).await?;
        self.send_email("security@company.com", "EMERGENCY JIT APPROVAL", &message).await?;
        
        Ok(())
    }
    
    async fn send_slack_message(&self, channel: &str, message: &str) -> Result<()> {
        // Implementation would use Slack webhook or API
        info!("Slack notification to {}: {}", channel, message);
        Ok(())
    }
    
    async fn send_email(&self, to: &str, subject: &str, body: &str) -> Result<()> {
        // Implementation would use SMTP or email API
        info!("Email to {}: {} - {}", to, subject, body);
        Ok(())
    }
    
    async fn send_user_notification(&self, user: &str, message: &str) -> Result<()> {
        // Could be email, SMS, push notification, etc.
        info!("User notification to {}: {}", user, message);
        Ok(())
    }
}

/// Storage trait for approval requests
#[async_trait::async_trait]
pub trait ApprovalStorage {
    async fn store_request(&self, request: &PendingRequest) -> Result<()>;
    async fn load_request(&self, request_id: &str) -> Result<Option<PendingRequest>>;
    async fn list_requests_by_status(&self, status: RequestStatus) -> Result<Vec<PendingRequest>>;
    async fn list_requests_by_user(&self, user: &str) -> Result<Vec<PendingRequest>>;
}

/// Example CLI integration
pub struct ApprovalCLI {
    workflow: ApprovalWorkflow,
}

impl ApprovalCLI {
    pub fn new(workflow: ApprovalWorkflow) -> Self {
        Self { workflow }
    }
    
    /// Replace the old auto-approval request command
    pub async fn request_access(
        &self,
        user: &str,
        command: &str,
        justification: &str,
        ttl: &str,
    ) -> Result<()> {
        let ttl_seconds = parse_ttl(ttl)?;
        
        let metadata = RequestMetadata {
            host_fingerprint: get_host_fingerprint()?,
            client_ip: None,
            user_agent: Some("jitctl".to_string()),
            ticket_ref: std::env::var("JIT_TICKET").ok(),
            emergency: std::env::var("JIT_EMERGENCY").is_ok(),
            production_impact: command.to_lowercase().contains("prod"),
        };
        
        let request_id = self.workflow.submit_request(
            user, command, justification, ttl_seconds, metadata
        ).await?;
        
        println!("📋 Access request submitted: {}", request_id);
        println!("⏳ Waiting for admin approval...");
        println!("📧 Admins have been notified");
        println!("\nCheck status: jitctl status --request {}", request_id);
        
        Ok(())
    }
    
    /// Admin commands for approval management
    pub async fn list_pending(&self, admin_user: &str) -> Result<()> {
        let requests = self.workflow.list_pending_requests(admin_user).await?;
        
        if requests.is_empty() {
            println!("No pending requests");
            return Ok(());
        }
        
        println!("Pending JIT Access Requests:");
        println!("┌──────────────────┬──────────┬─────────────────────┬──────┬─────────────┐");
        println!("│ Request ID       │ User     │ Command             │ Risk │ Expires     │");
        println!("├──────────────────┼──────────┼─────────────────────┼──────┼─────────────┤");
        
        for req in requests {
            println!("│ {:<16} │ {:<8} │ {:<19} │ {:<4} │ {} │",
                    &req.id[..16], 
                    req.user,
                    if req.command.len() > 19 { &req.command[..19] } else { &req.command },
                    req.risk_score,
                    req.expires_at.format("%m-%d %H:%M"));
        }
        
        println!("└──────────────────┴──────────┴─────────────────────┴──────┴─────────────┘");
        
        Ok(())
    }
    
    pub async fn approve_request(
        &self,
        request_id: &str,
        approver: &str,
        comment: Option<String>,
        override_ttl: Option<u64>,
    ) -> Result<()> {
        let decision = ApprovalDecision {
            request_id: request_id.to_string(),
            decision: RequestStatus::Approved,
            approver: approver.to_string(),
            comment,
            override_ttl,
            conditions: vec![],
        };
        
        let _token = self.workflow.approve_request(decision).await?;
        println!("✅ Request {} approved", request_id);
        
        Ok(())
    }
    
    pub async fn deny_request(
        &self,
        request_id: &str,
        approver: &str,
        reason: String,
    ) -> Result<()> {
        let decision = ApprovalDecision {
            request_id: request_id.to_string(),
            decision: RequestStatus::Denied,
            approver: approver.to_string(),
            comment: Some(reason),
            override_ttl: None,
            conditions: vec![],
        };
        
        self.workflow.approve_request(decision).await?;
        println!("❌ Request {} denied", request_id);
        
        Ok(())
    }
}

// Helper functions (would be in separate modules)
fn parse_ttl(ttl: &str) -> Result<u64> {
    // TTL parsing implementation
    Ok(3600) // 1 hour default
}

fn get_host_fingerprint() -> Result<String> {
    // Host fingerprint implementation
    Ok("test-host".to_string())
}

/*
Usage example:

// Initialize approval workflow
let storage = Box::new(SqliteApprovalStorage::new("/var/lib/jit-sudo/approvals.db")?);
let workflow = ApprovalWorkflow::new(storage);
let cli = ApprovalCLI::new(workflow);

// User requests access (replaces auto-approval)
cli.request_access("alice", "systemctl restart nginx", "Fix memory leak in prod", "30m").await?;

// Admin approves request
cli.approve_request("req-12345", "bob", Some("Approved for hotfix".to_string()), None).await?;

// Emergency approval
workflow.emergency_approve("req-67890", "security_admin", "INC-2025-001").await?;
*/