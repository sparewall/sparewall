//! Appliance metrics in the Prometheus text format (design: "Metrics").
//! Host metrics (CPU, NIC counters) come from node_exporter, not here.

use std::collections::BTreeMap;
use std::fmt::Write;

use serde_json::Value;

use crate::Error;
use crate::coordinator::Coordinator;
use crate::health::Level;
use crate::system::System;

struct Out(String);

impl Out {
    fn help(&mut self, name: &str, kind: &str, help: &str) {
        writeln!(self.0, "# HELP {name} {help}").unwrap();
        writeln!(self.0, "# TYPE {name} {kind}").unwrap();
    }

    fn sample(&mut self, name: &str, labels: &[(&str, &str)], value: impl std::fmt::Display) {
        if labels.is_empty() {
            writeln!(self.0, "{name} {value}").unwrap();
        } else {
            let l: Vec<String> = labels
                .iter()
                .map(|(k, v)| format!("{k}=\"{}\"", escape(v)))
                .collect();
            writeln!(self.0, "{name}{{{}}} {value}", l.join(",")).unwrap();
        }
    }
}

fn escape(v: &str) -> String {
    v.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// Counters of every commented rule (`rule:…`, `raw:…`, `default:…`,
/// `forward:…`, `nat:…`) and set sizes, from `nft -j`.
pub fn nft_counters(json: &Value) -> (BTreeMap<String, (u64, u64)>, BTreeMap<String, usize>) {
    let mut counters: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut sets = BTreeMap::new();
    for item in json["nftables"].as_array().into_iter().flatten() {
        if let Some(rule) = item.get("rule") {
            let Some(comment) = rule["comment"].as_str() else {
                continue;
            };
            for e in rule["expr"].as_array().into_iter().flatten() {
                if let Some(c) = e.get("counter") {
                    let entry = counters.entry(comment.to_string()).or_default();
                    entry.0 += c["packets"].as_u64().unwrap_or(0);
                    entry.1 += c["bytes"].as_u64().unwrap_or(0);
                }
            }
        } else if let Some(set) = item.get("set") {
            let n = set["elem"].as_array().map_or(0, Vec::len);
            if let Some(name) = set["name"].as_str() {
                sets.insert(name.to_string(), n);
            }
        }
    }
    (counters, sets)
}

impl<S: System> Coordinator<S> {
    /// Render `/metrics`.
    pub fn metrics(&mut self) -> Result<String, Error> {
        let mut o = Out(String::new());
        let state = self.state()?;
        let (desired, applied) = self.hashes()?;

        o.help(
            "sparewall_generation",
            "gauge",
            "Live configuration generation (0 is bootstrap).",
        );
        o.sample("sparewall_generation", &[], state.active);
        o.help(
            "sparewall_generation_confirmed",
            "gauge",
            "Newest confirmed generation.",
        );
        o.sample("sparewall_generation_confirmed", &[], state.confirmed);
        o.help(
            "sparewall_confirm_pending",
            "gauge",
            "1 while a change waits for confirmation.",
        );
        o.sample(
            "sparewall_confirm_pending",
            &[],
            u8::from(state.pending.is_some()),
        );
        o.help(
            "sparewall_config_applied",
            "gauge",
            "1 when the running configuration is the desired one.",
        );
        o.sample(
            "sparewall_config_applied",
            &[],
            u8::from(applied.as_deref() == Some(desired.as_str())),
        );
        if let Some(ms) = self.last_apply_ms() {
            o.help(
                "sparewall_last_apply_duration_seconds",
                "gauge",
                "Duration of the last activation.",
            );
            o.sample(
                "sparewall_last_apply_duration_seconds",
                &[],
                ms as f64 / 1000.0,
            );
        }

        if let Some(t) = crate::backup::read_last(self.store().root())
            .and_then(|l| l.success)
            .and_then(|t| t.parse::<jiff::Timestamp>().ok())
        {
            o.help(
                "sparewall_backup_last_success_timestamp_seconds",
                "gauge",
                "When the newest successful backup finished.",
            );
            o.sample(
                "sparewall_backup_last_success_timestamp_seconds",
                &[],
                t.as_second(),
            );
        }

        let health = self.health()?;
        let level = |l: Level| match l {
            Level::Ok => 0,
            Level::Degraded => 1,
            Level::Failed => 2,
        };
        o.help(
            "sparewall_health_level",
            "gauge",
            "0 ok, 1 degraded, 2 failed.",
        );
        o.sample("sparewall_health_level", &[], level(health.level));
        o.help(
            "sparewall_health_check_level",
            "gauge",
            "Each health check: 0 ok, 1 degraded, 2 failed.",
        );
        for c in &health.checks {
            o.sample(
                "sparewall_health_check_level",
                &[("check", &c.name)],
                level(c.level),
            );
        }

        if let Ok(Some(json)) = self.system().nft_json() {
            let (counters, sets) = nft_counters(&json);
            o.help(
                "sparewall_rule_packets_total",
                "counter",
                "Packets matched, by rule.",
            );
            for (rule, (p, _)) in &counters {
                o.sample("sparewall_rule_packets_total", &[("rule", rule)], p);
            }
            o.help(
                "sparewall_rule_bytes_total",
                "counter",
                "Bytes matched, by rule.",
            );
            for (rule, (_, b)) in &counters {
                o.sample("sparewall_rule_bytes_total", &[("rule", rule)], b);
            }
            o.help(
                "sparewall_set_elements",
                "gauge",
                "Elements in each named set.",
            );
            for (set, n) in &sets {
                o.sample("sparewall_set_elements", &[("set", set)], n);
            }
        }

        for (key, name, help) in [
            (
                "net/netfilter/nf_conntrack_count",
                "sparewall_conntrack_entries",
                "Connection-tracking entries.",
            ),
            (
                "net/netfilter/nf_conntrack_max",
                "sparewall_conntrack_max",
                "Connection-tracking table size.",
            ),
        ] {
            if let Some(v) = self
                .system()
                .proc_sys(key)
                .and_then(|v| v.parse::<u64>().ok())
            {
                o.help(name, "gauge", help);
                o.sample(name, &[], v);
            }
        }

        let links = self.system().link_states();
        o.help(
            "sparewall_link_up",
            "gauge",
            "1 when the interface is operationally up.",
        );
        for (l, s) in &links {
            o.sample(
                "sparewall_link_up",
                &[("link", l)],
                u8::from(s == "up" || s == "unknown"),
            );
        }
        Ok(o.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_rules_and_sets() {
        let json: Value = serde_json::from_str(
            r#"{"nftables":[
              {"set":{"name":"admin_nets","elem":["10.0.0.0/8", "192.0.2.1"]}},
              {"set":{"name":"wan_address"}},
              {"rule":{"comment":"rule:wan->self:ssh","expr":[{"match":{}},{"counter":{"packets":3,"bytes":180}},{"accept":null}]}},
              {"rule":{"expr":[{"counter":{"packets":9,"bytes":9}}]}}
            ]}"#,
        )
        .unwrap();
        let (c, s) = nft_counters(&json);
        assert_eq!(c["rule:wan->self:ssh"], (3, 180));
        assert_eq!(c.len(), 1);
        assert_eq!(s["admin_nets"], 2);
        assert_eq!(s["wan_address"], 0);
    }

    #[test]
    fn escapes_labels() {
        assert_eq!(escape("a\"b\\c"), "a\\\"b\\\\c");
    }
}
