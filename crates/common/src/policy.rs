use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityType {
    #[serde(rename = "network.connect")]
    NetworkConnect,
    #[serde(rename = "database.read")]
    DatabaseRead,
    #[serde(rename = "database.write")]
    DatabaseWrite,
    #[serde(rename = "filesystem.read")]
    FilesystemRead,
    #[serde(rename = "filesystem.write")]
    FilesystemWrite,
    #[serde(rename = "process.execute")]
    ProcessExecute,
    #[serde(rename = "admin.operation")]
    AdminOperation,
    #[serde(rename = "session.authenticate")]
    SessionAuthenticate,
    #[serde(untagged)]
    Custom(String),
}

impl CapabilityType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::NetworkConnect => "network.connect",
            Self::DatabaseRead => "database.read",
            Self::DatabaseWrite => "database.write",
            Self::FilesystemRead => "filesystem.read",
            Self::FilesystemWrite => "filesystem.write",
            Self::ProcessExecute => "process.execute",
            Self::AdminOperation => "admin.operation",
            Self::SessionAuthenticate => "session.authenticate",
            Self::Custom(s) => s.as_str(),
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "network.connect" => Self::NetworkConnect,
            "database.read" => Self::DatabaseRead,
            "database.write" => Self::DatabaseWrite,
            "filesystem.read" => Self::FilesystemRead,
            "filesystem.write" => Self::FilesystemWrite,
            "process.execute" => Self::ProcessExecute,
            "admin.operation" => Self::AdminOperation,
            "session.authenticate" => Self::SessionAuthenticate,
            other => Self::Custom(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PermissionState {
    Granted,
    Denied,
    Restricted,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyRule {
    pub capability: String,
    pub scope: String, // exact string, glob pattern like "/app/data/**", or "*"
    pub description: Option<String>,
}

impl PolicyRule {
    pub fn matches(&self, capability: &str, resource: &str) -> bool {
        // Match capability
        if self.capability != "*" && self.capability != capability {
            return false;
        }

        // Match resource scope
        match_scope_pattern(&self.scope, resource)
    }
}

pub fn match_scope_pattern(pattern: &str, target: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern == target {
        return true;
    }

    // Glob prefix matching e.g. "/app/data/**" or "/etc/*"
    if pattern.ends_with("/**") {
        let prefix = &pattern[..pattern.len() - 3];
        return target.starts_with(prefix);
    }
    if pattern.ends_with("/*") {
        let prefix = &pattern[..pattern.len() - 2];
        if target.starts_with(prefix) {
            let remainder = &target[prefix.len()..];
            return !remainder.trim_start_matches('/').contains('/');
        }
    }

    // Suffix wildcard matching e.g. "*.internal:*"
    if pattern.starts_with("*.") {
        let suffix = &pattern[1..];
        return target.ends_with(suffix);
    }

    false
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyBundle {
    pub policy_id: String,
    pub version: u32,
    pub target_app: String, // app_id or "*"
    pub description: String,
    pub allow: Vec<PolicyRule>,
    pub deny: Vec<PolicyRule>,
    #[serde(default)]
    pub default_allow: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DecisionOutcome {
    Allow,
    Deny,
    Revoke,
    Restrict,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyDecision {
    pub decision_id: Uuid,
    pub who: String,
    pub app_id: String,
    pub capability: String,
    pub target_resource: String,
    pub policy_id: String,
    pub decision: DecisionOutcome,
    pub reason: String,
    pub matched_rule: Option<String>,
    pub is_simulation: bool,
    pub evidence_event_ids: Vec<Uuid>,
    pub timestamp: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scope_pattern_matching() {
        assert!(match_scope_pattern("*", "/etc/shadow"));
        assert!(match_scope_pattern("/app/data/**", "/app/data/user/1.json"));
        assert!(!match_scope_pattern("/app/data/**", "/etc/shadow"));
        assert!(match_scope_pattern("postgres.internal:5432", "postgres.internal:5432"));
        assert!(!match_scope_pattern("postgres.internal:5432", "redis.internal:6379"));
    }

    #[test]
    fn test_policy_rule_evaluation() {
        let rule = PolicyRule {
            capability: "database.read".into(),
            scope: "/app/data/**".into(),
            description: None,
        };

        assert!(rule.matches("database.read", "/app/data/tables/orders"));
        assert!(!rule.matches("database.write", "/app/data/tables/orders"));
        assert!(!rule.matches("database.read", "/secret/keys"));
    }
}
