//! Foreign Function Interface for C plugin

use crate::{ExecContext, Decision, grant::GrantVerifier, audit::AuditLogger};
use std::ffi::{CStr, CString, c_char};
use std::collections::HashMap;

/// C-compatible execution context
#[repr(C)]
pub struct CExecContext {
    pub user: *const c_char,
    pub runas: *const c_char,
    pub command: *const c_char,
    pub argv: *const *const c_char,
    pub argc: i32,
    pub cwd: *const c_char,
    pub host_id: *const c_char,
}

/// C-compatible decision result
#[repr(C)]
pub struct CDecision {
    pub allowed: bool,
    pub reason: *const c_char,
    pub grant_id: *const c_char,
}

/// Validate a grant against execution context (C API)
#[no_mangle]
pub unsafe extern "C" fn validate_grant_c(
    grant_token: *const c_char,
    ctx: *const CExecContext,
    result: *mut CDecision,
) -> i32 {
    if grant_token.is_null() || ctx.is_null() || result.is_null() {
        return -1;
    }
    
    // Convert C strings to Rust
    let token_str = match CStr::from_ptr(grant_token).to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };
    
    let user = match CStr::from_ptr((*ctx).user).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };
    
    let runas = match CStr::from_ptr((*ctx).runas).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };
    
    let command = match CStr::from_ptr((*ctx).command).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -1,
    };
    
    // Convert argv
    let mut argv = Vec::new();
    for i in 0..(*ctx).argc {
        let arg_ptr = *(*ctx).argv.offset(i as isize);
        if !arg_ptr.is_null() {
            match CStr::from_ptr(arg_ptr).to_str() {
                Ok(s) => argv.push(s.to_string()),
                Err(_) => return -1,
            }
        }
    }
    
    let exec_ctx = ExecContext {
        user,
        runas,
        command,
        argv,
        cwd: "/".to_string(), // Default
        env: HashMap::new(),   // Empty for now
        host_id: "localhost".to_string(), // Default
        timestamp: chrono::Utc::now().timestamp(),
    };
    
    // Verify grant
    let verifier = GrantVerifier::new(vec!["https://jit-broker.example.com".to_string()]);
    let decision = match verifier.verify_grant(token_str) {
        Ok(grant) => {
            if verifier.matches_context(&grant, &exec_ctx) {
                Decision {
                    allowed: true,
                    reason: "Grant valid and matches context".to_string(),
                    grant_id: Some(grant.jti.clone()),
                    ttl_remaining: Some(grant.exp - exec_ctx.timestamp),
                }
            } else {
                Decision {
                    allowed: false,
                    reason: "Grant does not match execution context".to_string(),
                    grant_id: Some(grant.jti),
                    ttl_remaining: None,
                }
            }
        }
        Err(e) => Decision {
            allowed: false,
            reason: format!("Grant verification failed: {}", e),
            grant_id: None,
            ttl_remaining: None,
        },
    };
    
    // Convert result back to C
    (*result).allowed = decision.allowed;
    
    // Note: In a real implementation, we would need to manage memory properly
    // These strings need to be allocated and freed appropriately
    let reason_cstr = CString::new(decision.reason).unwrap();
    (*result).reason = reason_cstr.into_raw();
    
    if let Some(ref grant_id) = decision.grant_id {
        let grant_id_cstr = CString::new(grant_id.clone()).unwrap();
        (*result).grant_id = grant_id_cstr.into_raw();
    } else {
        (*result).grant_id = std::ptr::null();
    }
    
    // Log audit event
    let auditor = AuditLogger::new();
    let _ = auditor.log_grant_check(&exec_ctx, decision.allowed, 
                                    decision.grant_id.as_deref());
    
    0 // Success
}

/// Free memory allocated by validate_grant_c
#[no_mangle]
pub unsafe extern "C" fn free_decision_c(decision: *mut CDecision) {
    if decision.is_null() {
        return;
    }
    
    if !(*decision).reason.is_null() {
        let _ = CString::from_raw((*decision).reason as *mut c_char);
    }
    
    if !(*decision).grant_id.is_null() {
        let _ = CString::from_raw((*decision).grant_id as *mut c_char);
    }
}
