use crate::{EnforcementBackend, EnforcerError};
use async_trait::async_trait;
use security_control_plane_common::{ContainmentActionType, SignedContainmentCommand};
use std::net::IpAddr;
use tokio::process::Command;
use tracing::{error, info};
use uuid::Uuid;

pub struct SystemEnforcementBackend;

impl SystemEnforcementBackend {
    pub fn new() -> Self {
        Self
    }

    async fn run_nft(args: &[&str]) -> Result<String, EnforcerError> {
        let output = Command::new("nft")
            .args(args)
            .output()
            .await
            .map_err(|err| EnforcerError::CommandStart(err.to_string()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            error!(stderr = %stderr, "nftables command failed");
            return Err(EnforcerError::CommandFailed(stderr));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    async fn block_ip(&self, command: &SignedContainmentCommand) -> Result<(), EnforcerError> {
        let raw_ip = command
            .params
            .get("ip")
            .map(String::as_str)
            .or_else(|| command.target_entity.strip_prefix("ip:"))
            .ok_or_else(|| EnforcerError::InvalidTarget("missing IP address".into()))?;
        let ip: IpAddr = raw_ip
            .parse()
            .map_err(|_| EnforcerError::InvalidTarget("target is not a valid IP address".into()))?;
        let chain = command
            .params
            .get("chain")
            .map(String::as_str)
            .unwrap_or("input");
        if !is_safe_identifier(chain) {
            return Err(EnforcerError::InvalidTarget(
                "nftables chain name must be an identifier".into(),
            ));
        }

        let family = if ip.is_ipv4() { "ip" } else { "ip6" };
        let target = ip.to_string();
        let id_comment = format!("corvus-{id}", id = command.command_id);
        Self::run_nft(&[
            "add",
            "rule",
            "inet",
            "filter",
            chain,
            family,
            "saddr",
            &target,
            "comment",
            &id_comment,
            "drop",
        ])
        .await?;
        info!(ip = %ip, command_id = %command.command_id, "Added nftables DROP rule");
        Ok(())
    }

    async fn remove_block(&self, command: &SignedContainmentCommand) -> Result<(), EnforcerError> {
        let chain = command
            .params
            .get("chain")
            .map(String::as_str)
            .unwrap_or("input");
        if !is_safe_identifier(chain) {
            return Err(EnforcerError::InvalidTarget(
                "nftables chain name must be an identifier".into(),
            ));
        }

        let rules = Self::run_nft(&["-a", "list", "chain", "inet", "filter", chain]).await?;
        let Some(handle) = find_rule_handle(&rules, command.command_id) else {
            return Ok(());
        };
        Self::run_nft(&[
            "delete",
            "rule",
            "inet",
            "filter",
            chain,
            "handle",
            &handle.to_string(),
        ])
        .await?;
        Ok(())
    }

    async fn kill_process(&self, command: &SignedContainmentCommand) -> Result<(), EnforcerError> {
        let raw_pid = command
            .params
            .get("pid")
            .map(String::as_str)
            .or_else(|| command.target_entity.strip_prefix("pid:"))
            .ok_or_else(|| EnforcerError::InvalidTarget("missing process ID".into()))?;
        let pid: u32 = raw_pid
            .parse()
            .map_err(|_| EnforcerError::InvalidTarget("process ID must be numeric".into()))?;
        if pid <= 1 || pid == std::process::id() {
            return Err(EnforcerError::InvalidTarget(
                "refusing to terminate PID 1 or the enforcer process".into(),
            ));
        }

        #[cfg(target_os = "linux")]
        {
            let status = Command::new("kill")
                .arg("-KILL")
                .arg("--")
                .arg(pid.to_string())
                .status()
                .await
                .map_err(|err| EnforcerError::CommandStart(err.to_string()))?;
            if !status.success() {
                return Err(EnforcerError::CommandFailed(format!(
                    "kill returned status {status}"
                )));
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            Err(EnforcerError::UnsupportedAction)
        }
    }
}

impl Default for SystemEnforcementBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EnforcementBackend for SystemEnforcementBackend {
    async fn execute(&self, command: &SignedContainmentCommand) -> Result<(), EnforcerError> {
        match &command.action {
            ContainmentActionType::NftablesBlock => self.block_ip(command).await,
            ContainmentActionType::KillProcess => self.kill_process(command).await,
            _ => Err(EnforcerError::UnsupportedAction),
        }
    }

    async fn rollback(&self, command: &SignedContainmentCommand) -> Result<(), EnforcerError> {
        match &command.action {
            ContainmentActionType::NftablesBlock => self.remove_block(command).await,
            _ => Err(EnforcerError::UnsupportedAction),
        }
    }
}

fn is_safe_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn find_rule_handle(listing: &str, command_id: Uuid) -> Option<u64> {
    let marker = format!("corvus-{command_id}");
    listing.lines().find_map(|line| {
        if !line.contains(&marker) {
            return None;
        }
        let (_, handle) = line.rsplit_once("# handle ")?;
        handle.trim().parse().ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_only_the_handle_for_its_command_id() {
        let wanted = Uuid::new_v4();
        let unrelated = Uuid::new_v4();
        let listing = format!(
            "ip saddr 192.0.2.1 drop comment \"corvus-{unrelated}\" # handle 8\n\
             ip saddr 192.0.2.2 drop comment \"corvus-{wanted}\" # handle 12\n"
        );

        assert_eq!(find_rule_handle(&listing, wanted), Some(12));
    }

    #[test]
    fn rejects_invalid_chain_identifiers() {
        assert!(!is_safe_identifier("input; flush ruleset"));
        assert!(is_safe_identifier("input_chain"));
    }
}
