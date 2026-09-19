use chrono::{DateTime, Utc};
use security_control_plane_common::SecurityEvent;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use tracing::info;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum EntityType {
    Host,
    Session,
    Workload,
    User,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CanonicalEntity {
    pub entity_id: String,
    pub entity_type: EntityType,
    pub display_name: String,
    pub linked_ips: HashSet<String>,
    pub linked_sessions: HashSet<String>,
    pub linked_user_ids: HashSet<String>,
    pub linked_containers: HashSet<String>,
    pub linked_pids: HashSet<u32>,
    pub apps_seen: HashSet<String>,
    pub exercised_capabilities: HashSet<String>,
    pub risk_score: u32,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub event_count: u64,
}

impl CanonicalEntity {
    pub fn new(entity_id: String, entity_type: EntityType, display_name: String) -> Self {
        let now = Utc::now();
        Self {
            entity_id,
            entity_type,
            display_name,
            linked_ips: HashSet::new(),
            linked_sessions: HashSet::new(),
            linked_user_ids: HashSet::new(),
            linked_containers: HashSet::new(),
            linked_pids: HashSet::new(),
            apps_seen: HashSet::new(),
            exercised_capabilities: HashSet::new(),
            risk_score: 0,
            first_seen: now,
            last_seen: now,
            event_count: 0,
        }
    }

    pub fn merge(&mut self, other: CanonicalEntity) {
        self.linked_ips.extend(other.linked_ips);
        self.linked_sessions.extend(other.linked_sessions);
        self.linked_user_ids.extend(other.linked_user_ids);
        self.linked_containers.extend(other.linked_containers);
        self.linked_pids.extend(other.linked_pids);
        self.apps_seen.extend(other.apps_seen);
        self.exercised_capabilities.extend(other.exercised_capabilities);
        self.event_count += other.event_count;
        self.risk_score = self.risk_score.max(other.risk_score);
        if other.first_seen < self.first_seen {
            self.first_seen = other.first_seen;
        }
        if other.last_seen > self.last_seen {
            self.last_seen = other.last_seen;
        }
    }
}

pub struct IdentityResolver {
    /// Maps alias strings (e.g. "ip:1.2.3.4", "session:abc", "user:alice") to canonical entity_id
    alias_to_canonical: HashMap<String, String>,
    /// Maps canonical entity_id to CanonicalEntity
    entities: HashMap<String, CanonicalEntity>,
}

impl Default for IdentityResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl IdentityResolver {
    pub fn new() -> Self {
        Self {
            alias_to_canonical: HashMap::new(),
            entities: HashMap::new(),
        }
    }

    /// Extract all alias keys from a security event
    pub fn extract_aliases(event: &SecurityEvent) -> Vec<(String, EntityType, String)> {
        let mut aliases = Vec::new();

        if let Some(actor) = &event.actor {
            if let Some(uid) = &actor.user_id {
                if !uid.trim().is_empty() {
                    aliases.push((format!("user:{}", uid), EntityType::User, uid.clone()));
                }
            }
            if let Some(sid) = &actor.session_id {
                if !sid.trim().is_empty() {
                    aliases.push((format!("session:{}", sid), EntityType::Session, sid.clone()));
                }
            }
        }

        if let Some(cid) = &event.source.container_id {
            if !cid.trim().is_empty() {
                aliases.push((format!("container:{}", cid), EntityType::Workload, cid.clone()));
            }
        }

        if let Some(ip) = &event.source.ip {
            if !ip.trim().is_empty() {
                aliases.push((format!("ip:{}", ip), EntityType::Host, ip.clone()));
            }
        }

        aliases
    }

    /// Ingest a security event, link all present identifiers, and return the resolved canonical entity_id
    pub fn resolve_and_update(&mut self, event: &SecurityEvent) -> String {
        let aliases = Self::extract_aliases(event);
        if aliases.is_empty() {
            let fallback_id = format!("canonical:app:{}", event.app_id);
            let entity = self.entities.entry(fallback_id.clone()).or_insert_with(|| {
                CanonicalEntity::new(fallback_id.clone(), EntityType::Host, event.app_id.clone())
            });
            entity.last_seen = event.timestamp;
            entity.event_count += 1;
            entity.apps_seen.insert(event.app_id.clone());
            return fallback_id;
        }

        // Find existing canonical entity IDs for these aliases
        let mut matched_canonical_ids: Vec<String> = aliases
            .iter()
            .filter_map(|(alias, _, _)| self.alias_to_canonical.get(alias).cloned())
            .collect();
        matched_canonical_ids.sort();
        matched_canonical_ids.dedup();

        let canonical_id = if matched_canonical_ids.is_empty() {
            // Pick strongest alias to initialize canonical entity ID:
            // User > Workload > Session > Host
            let (best_alias, best_type, display_name) = aliases
                .iter()
                .max_by_key(|(_, et, _)| *et)
                .cloned()
                .unwrap();
            let new_id = format!("canonical:{}", best_alias);
            let mut entity = CanonicalEntity::new(new_id.clone(), best_type, display_name);
            entity.first_seen = event.timestamp;
            self.entities.insert(new_id.clone(), entity);
            new_id
        } else if matched_canonical_ids.len() == 1 {
            matched_canonical_ids[0].clone()
        } else {
            // Multiple existing entities found — merge them into the highest priority entity
            let mut highest_id = matched_canonical_ids[0].clone();
            let mut highest_type = self.entities.get(&highest_id).map(|e| e.entity_type).unwrap_or(EntityType::Host);

            for id in &matched_canonical_ids[1..] {
                if let Some(e) = self.entities.get(id) {
                    if e.entity_type > highest_type {
                        highest_type = e.entity_type;
                        highest_id = id.clone();
                    }
                }
            }

            // Merge all other entities into highest_id
            for id in matched_canonical_ids {
                if id != highest_id {
                    if let Some(other_entity) = self.entities.remove(&id) {
                        info!("Merging canonical entity {} into {}", id, highest_id);
                        if let Some(target) = self.entities.get_mut(&highest_id) {
                            target.merge(other_entity);
                        }
                        // Update all alias pointers that mapped to `id`
                        for (_, target_id) in self.alias_to_canonical.iter_mut() {
                            if *target_id == id {
                                *target_id = highest_id.clone();
                            }
                        }
                    }
                }
            }
            highest_id
        };

        // Link all current event aliases to this canonical_id
        for (alias, _, _) in &aliases {
            self.alias_to_canonical.insert(alias.clone(), canonical_id.clone());
        }

        // Update entity state with details from this event
        if let Some(entity) = self.entities.get_mut(&canonical_id) {
            if let Some(ip) = &event.source.ip {
                entity.linked_ips.insert(ip.clone());
            }
            if let Some(actor) = &event.actor {
                if let Some(uid) = &actor.user_id {
                    entity.linked_user_ids.insert(uid.clone());
                    // If we now have a verified user_id and this entity was just a Host, elevate it
                    if entity.entity_type < EntityType::User {
                        entity.entity_type = EntityType::User;
                        entity.display_name = uid.clone();
                    }
                }
                if let Some(sid) = &actor.session_id {
                    entity.linked_sessions.insert(sid.clone());
                }
            }
            if let Some(cid) = &event.source.container_id {
                entity.linked_containers.insert(cid.clone());
            }
            if let Some(pid) = event.source.pid {
                entity.linked_pids.insert(pid);
            }
            entity.apps_seen.insert(event.app_id.clone());
            entity.event_count += 1;
            if event.timestamp > entity.last_seen {
                entity.last_seen = event.timestamp;
            }
        }

        canonical_id
    }

    /// Retrieve canonical entity by any known alias (e.g. "ip:198.51.100.1", "session:xyz")
    pub fn get_by_alias(&self, alias: &str) -> Option<&CanonicalEntity> {
        let canonical_id = self.alias_to_canonical.get(alias)?;
        self.entities.get(canonical_id)
    }

    pub fn get(&self, canonical_id: &str) -> Option<&CanonicalEntity> {
        self.entities.get(canonical_id)
    }

    pub fn get_mut(&mut self, canonical_id: &str) -> Option<&mut CanonicalEntity> {
        self.entities.get_mut(canonical_id)
    }

    pub fn list_entities(&self) -> Vec<CanonicalEntity> {
        let mut list: Vec<CanonicalEntity> = self.entities.values().cloned().collect();
        list.sort_by(|a, b| b.last_seen.cmp(&a.last_seen));
        list
    }

    pub fn entity_count(&self) -> usize {
        self.entities.len()
    }
}
