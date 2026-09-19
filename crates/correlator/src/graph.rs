use crate::capability::CapabilityType;
use chrono::{DateTime, Utc};
use security_control_plane_common::SecurityEvent;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeCategory {
    Entity,
    Application,
    Resource,
    Endpoint,
    Host,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub category: NodeCategory,
    pub label: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub hit_count: u64,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub relation: String,
    pub count: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub weight: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

pub struct MemoryContextGraph {
    nodes: HashMap<String, GraphNode>,
    edges: HashMap<String, GraphEdge>,
    ttl_seconds: i64,
}

impl Default for MemoryContextGraph {
    fn default() -> Self {
        Self::new(3600) // Default 1 hour correlation retention window
    }
}

impl MemoryContextGraph {
    pub fn new(ttl_seconds: i64) -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            ttl_seconds,
        }
    }

    fn ensure_node(&mut self, id: String, category: NodeCategory, label: String, ts: DateTime<Utc>) {
        if let Some(node) = self.nodes.get_mut(&id) {
            node.hit_count += 1;
            if ts > node.last_seen {
                node.last_seen = ts;
            }
        } else {
            self.nodes.insert(
                id.clone(),
                GraphNode {
                    id,
                    category,
                    label,
                    first_seen: ts,
                    last_seen: ts,
                    hit_count: 1,
                    metadata: HashMap::new(),
                },
            );
        }
    }

    fn record_edge(
        &mut self,
        source: String,
        target: String,
        relation: String,
        ts: DateTime<Utc>,
        weight_increment: f32,
    ) {
        let edge_id = format!("{}-{}-{}", source, relation, target);
        if let Some(edge) = self.edges.get_mut(&edge_id) {
            edge.count += 1;
            edge.weight += weight_increment;
            if ts > edge.last_seen {
                edge.last_seen = ts;
            }
        } else {
            self.edges.insert(
                edge_id.clone(),
                GraphEdge {
                    id: edge_id,
                    source,
                    target,
                    relation,
                    count: 1,
                    first_seen: ts,
                    last_seen: ts,
                    weight: weight_increment,
                },
            );
        }
    }

    pub fn record_event(
        &mut self,
        event: &SecurityEvent,
        canonical_id: &str,
        capabilities: &[CapabilityType],
    ) {
        let ts = event.timestamp;

        // 1. Entity Node
        self.ensure_node(
            canonical_id.to_string(),
            NodeCategory::Entity,
            canonical_id.to_string(),
            ts,
        );

        // 2. Application Node
        let app_node_id = format!("app:{}", event.app_id);
        self.ensure_node(
            app_node_id.clone(),
            NodeCategory::Application,
            event.app_id.clone(),
            ts,
        );

        // Edge: Entity -> App
        let app_relation = if event.event_type.starts_with("auth.") {
            "AUTHENTICATES_ON"
        } else {
            "ACCESSES"
        };
        self.record_edge(
            canonical_id.to_string(),
            app_node_id.clone(),
            app_relation.to_string(),
            ts,
            1.0,
        );

        // 3. Endpoint Node
        if let Some(action) = &event.action {
            if let Some(endpoint) = &action.endpoint {
                let ep_node_id = format!("endpoint:{}:{}", event.app_id, endpoint);
                self.ensure_node(
                    ep_node_id.clone(),
                    NodeCategory::Endpoint,
                    format!("{} {}", action.method.as_deref().unwrap_or("REQ"), endpoint),
                    ts,
                );

                let ep_relation = if action.status_code.map(|sc| sc >= 400).unwrap_or(false) {
                    "PROBED"
                } else {
                    "CALLS"
                };

                self.record_edge(
                    canonical_id.to_string(),
                    ep_node_id.clone(),
                    ep_relation.to_string(),
                    ts,
                    1.0,
                );

                // Edge: App -> Endpoint
                self.record_edge(
                    app_node_id.clone(),
                    ep_node_id,
                    "EXPOSES".to_string(),
                    ts,
                    0.5,
                );
            }
        }

        // 4. Resource Node
        if let Some(res) = &event.resource {
            if let Some(rid) = &res.resource_id {
                let res_node_id = format!("resource:{}", rid);
                self.ensure_node(
                    res_node_id.clone(),
                    NodeCategory::Resource,
                    rid.clone(),
                    ts,
                );

                self.record_edge(
                    canonical_id.to_string(),
                    res_node_id,
                    "TARGETS".to_string(),
                    ts,
                    1.5,
                );
            }
        }

        // 5. Capability relations
        for cap in capabilities {
            let cap_node_id = format!("capability:{}", cap.as_str());
            self.ensure_node(
                cap_node_id.clone(),
                NodeCategory::Resource,
                cap.as_str().to_string(),
                ts,
            );

            self.record_edge(
                canonical_id.to_string(),
                cap_node_id,
                "EXERCISES".to_string(),
                ts,
                1.0,
            );
        }

        // 6. Host Node
        if let Some(ip) = &event.source.ip {
            let host_node_id = format!("host:{}", ip);
            self.ensure_node(host_node_id.clone(), NodeCategory::Host, ip.clone(), ts);
            self.record_edge(
                canonical_id.to_string(),
                host_node_id,
                "ORIGINATES_FROM".to_string(),
                ts,
                0.5,
            );
        }
    }

    /// Retrieve the connected subgraph for a given entity
    pub fn get_subgraph(&self, entity_id: &str) -> SubGraph {
        let mut relevant_node_ids = HashSet::new();
        relevant_node_ids.insert(entity_id.to_string());

        let mut matched_edges = Vec::new();
        for edge in self.edges.values() {
            if edge.source == entity_id || edge.target == entity_id {
                relevant_node_ids.insert(edge.source.clone());
                relevant_node_ids.insert(edge.target.clone());
                matched_edges.push(edge.clone());
            }
        }

        let matched_nodes: Vec<GraphNode> = relevant_node_ids
            .into_iter()
            .filter_map(|id| self.nodes.get(&id).cloned())
            .collect();

        SubGraph {
            nodes: matched_nodes,
            edges: matched_edges,
        }
    }

    /// Retrieve the full graph for dashboard rendering
    pub fn get_full_graph(&self) -> SubGraph {
        SubGraph {
            nodes: self.nodes.values().cloned().collect(),
            edges: self.edges.values().cloned().collect(),
        }
    }

    /// Prune stale nodes and edges older than ttl_seconds
    pub fn prune_expired(&mut self) -> usize {
        let cutoff = Utc::now() - chrono::Duration::seconds(self.ttl_seconds);
        let before_nodes = self.nodes.len();

        self.nodes.retain(|_, node| node.last_seen >= cutoff);
        self.edges
            .retain(|_, edge| edge.last_seen >= cutoff && self.nodes.contains_key(&edge.source) && self.nodes.contains_key(&edge.target));

        before_nodes - self.nodes.len()
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
}
