//! The local Prometheus (`metrics.mode: local`, #145; design: "Metrics").
//!
//! Each node keeps its own history: Prometheus, in its provider container,
//! scrapes the coordinator's `/metrics` (with node_exporter's host metrics
//! folded in) over loopback, where it answers without a token in this
//! mode, and itself. It listens on loopback only; the coordinator queries
//! it for the API (`org.sparewall.Metrics`). In a pair each node keeps its
//! own: a merged view is for an external Prometheus.

use std::fmt::Write;

use sparewall_config::model::{Document, MetricsMode};

use crate::{CheckSpec, Rendered, Service, Subsystem};

pub const UNIT: &str = "sparewall-prometheus.service";
pub const CONTAINER: &str = "sparewall-prometheus";
pub const CONF: &str = "prometheus.yml";
/// Where Prometheus listens: loopback, never the network.
pub const LISTEN: &str = "127.0.0.1:9090";
/// The coordinator's HTTPS listener, as Prometheus reaches it.
const COORDINATOR: &str = "127.0.0.1:443";
pub const DEFAULT_RETENTION: &str = "15d";
pub const DEFAULT_RETENTION_SIZE: &str = "1GB";
const SCRAPE_INTERVAL: &str = "15s";

pub(crate) fn render(doc: &Document, node: &str, out: &mut Rendered) {
    let Some(m) = doc
        .metrics
        .as_ref()
        .filter(|m| m.mode == MetricsMode::Local)
    else {
        return;
    };
    let time = m.retention.as_deref().unwrap_or(DEFAULT_RETENTION);
    let size = m
        .retention_size
        .as_deref()
        .unwrap_or(DEFAULT_RETENTION_SIZE);
    let mut s = String::from(crate::HEADER);
    // Validation keeps both to Prometheus's units, which need no quoting;
    // the node's name is a hostname.
    write!(
        s,
        "global:\n  scrape_interval: {SCRAPE_INTERVAL}\n\n\
         # The oldest goes first once either limit is reached.\n\
         storage:\n  tsdb:\n    retention:\n      time: {time}\n      size: {size}\n\n\
         scrape_configs:\n\
         \x20 # The coordinator's /metrics, with node_exporter's: on loopback it\n\
         \x20 # needs no token in this mode. Its certificate is for the\n\
         \x20 # management network's names, not loopback's.\n\
         \x20 - job_name: sparewall\n    scheme: https\n    tls_config:\n      insecure_skip_verify: true\n\
         \x20   static_configs:\n      - targets: [\"{COORDINATOR}\"]\n        labels:\n          instance: {node}\n\
         \x20 # Its own storage: how much history it holds.\n\
         \x20 - job_name: prometheus\n\
         \x20   static_configs:\n      - targets: [\"{LISTEN}\"]\n        labels:\n          instance: {node}\n"
    )
    .unwrap();
    out.add(Subsystem::Metrics, CONF, s);
    out.meta.services.insert(
        "metrics".into(),
        Service {
            provider: "prometheus".into(),
            unit: UNIT.into(),
            subsystem: Subsystem::Metrics,
            reload: true,
            management: true,
            check: Some(CheckSpec {
                container: Some(CONTAINER.into()),
                mount: "/etc/prometheus".into(),
                command: vec![
                    "promtool".into(),
                    "check".into(),
                    "config".into(),
                    format!("/etc/prometheus/{CONF}"),
                ],
                overrides: Default::default(),
            }),
        },
    );
}
