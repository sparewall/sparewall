//! The boundary between coordinator logic and the running system. The real
//! implementation is [`crate::linux::Linux`]; tests use [`Fake`].

use std::collections::BTreeMap;

use sparewall_render::{CheckSpec, Meta, Subsystem};

use crate::Error;

/// Files of one subsystem, by file name.
pub type Files = BTreeMap<String, String>;

pub trait System: Send {
    /// Check an nft table body (`nft -c`) as it would load over the live
    /// table, keeping `preserved` sets.
    fn nft_check(&mut self, body: &str, preserved: &[String]) -> Result<(), Error>;

    /// Load an nft table body in one transaction. Returns the preserved
    /// sets that did not exist before (so their links must be reconfigured
    /// for networkd to fill them).
    fn nft_load(&mut self, body: &str, preserved: &[String]) -> Result<Vec<String>, Error>;

    /// Chains in the live `inet sparewall` table, or `None` if it is absent.
    fn nft_chains(&mut self) -> Result<Option<Vec<String>>, Error>;

    /// Make `new` the live networkd configuration, replacing `old`, and
    /// bring links in line: rename ports, recreate changed netdevs, reload.
    /// With `early`, only install the files (before udev and networkd run).
    fn networkd_apply(&mut self, old: &Files, new: &Files, early: bool) -> Result<(), Error>;

    /// Reconfigure links so networkd re-applies their configuration.
    fn networkd_reconfigure(&mut self, links: &[String]) -> Result<(), Error>;

    /// Apply a sysctl.d-format file. Keys for interfaces that do not exist
    /// yet are skipped.
    fn sysctl_apply(&mut self, content: &str) -> Result<(), Error>;

    /// Operational state of each existing link (`up`, `down`, `unknown`...).
    fn link_states(&mut self) -> BTreeMap<String, String>;

    /// Install a provider subsystem's files (under `/run/sparewall/<dir>`).
    fn install_files(&mut self, sub: Subsystem, files: &Files) -> Result<(), Error>;

    /// Dry-run rendered files with the daemon's own checker.
    fn service_check(&mut self, spec: &CheckSpec, files: &Files) -> Result<(), Error>;

    /// Start the services a generation needs, reload or restart those whose
    /// files changed, and stop the provider services it does not need.
    fn services_apply(&mut self, meta: &Meta, changed: &[Subsystem]) -> Result<(), Error>;

    /// `systemctl is-active` state of each unit.
    fn unit_states(&mut self, units: &[String]) -> BTreeMap<String, String>;
}

/// A recording fake for tests.
#[derive(Debug, Default)]
pub struct Fake {
    pub log: Vec<String>,
    pub nft_body: Option<String>,
    pub network: Files,
    pub sysctl: Option<String>,
    pub links: BTreeMap<String, String>,
    /// Make `nft_check` fail with this message.
    pub fail_nft_check: Option<String>,
    /// Make `nft_load` fail with this message.
    pub fail_nft_load: Option<String>,
    pub existing_sets: Vec<String>,
    /// Provider files installed, by subsystem.
    pub installed: BTreeMap<Subsystem, Files>,
    /// Make `service_check` fail with this message.
    pub fail_service_check: Option<String>,
    /// Units started by `services_apply`.
    pub running: Vec<String>,
}

impl System for Fake {
    fn nft_check(&mut self, _body: &str, _preserved: &[String]) -> Result<(), Error> {
        self.log.push("nft-check".into());
        match &self.fail_nft_check {
            Some(m) => Err(Error::Check(m.clone())),
            None => Ok(()),
        }
    }

    fn nft_load(&mut self, body: &str, preserved: &[String]) -> Result<Vec<String>, Error> {
        self.log.push("nft-load".into());
        if let Some(m) = &self.fail_nft_load {
            return Err(Error::Apply(m.clone()));
        }
        self.nft_body = Some(body.to_string());
        let new: Vec<String> = preserved
            .iter()
            .filter(|s| !self.existing_sets.contains(s))
            .cloned()
            .collect();
        self.existing_sets.extend(new.iter().cloned());
        Ok(new)
    }

    fn nft_chains(&mut self) -> Result<Option<Vec<String>>, Error> {
        Ok(self.nft_body.as_ref().map(|b| {
            b.lines()
                .filter_map(|l| l.trim().strip_prefix("chain "))
                .map(|l| l.trim_end_matches(" {").to_string())
                .collect()
        }))
    }

    fn networkd_apply(&mut self, _old: &Files, new: &Files, early: bool) -> Result<(), Error> {
        self.log.push(
            if early {
                "networkd-install"
            } else {
                "networkd-apply"
            }
            .into(),
        );
        self.network = new.clone();
        Ok(())
    }

    fn networkd_reconfigure(&mut self, links: &[String]) -> Result<(), Error> {
        self.log.push(format!("reconfigure {}", links.join(",")));
        Ok(())
    }

    fn sysctl_apply(&mut self, content: &str) -> Result<(), Error> {
        self.log.push("sysctl".into());
        self.sysctl = Some(content.to_string());
        Ok(())
    }

    fn link_states(&mut self) -> BTreeMap<String, String> {
        self.links.clone()
    }

    fn install_files(&mut self, sub: Subsystem, files: &Files) -> Result<(), Error> {
        self.log.push(format!("install {}", sub.dir()));
        self.installed.insert(sub, files.clone());
        Ok(())
    }

    fn service_check(&mut self, spec: &CheckSpec, _files: &Files) -> Result<(), Error> {
        self.log.push(format!("check {}", spec.command.join(" ")));
        match &self.fail_service_check {
            Some(m) => Err(Error::Check(m.clone())),
            None => Ok(()),
        }
    }

    fn services_apply(&mut self, meta: &Meta, changed: &[Subsystem]) -> Result<(), Error> {
        let mut units: Vec<String> = meta.services.values().map(|s| s.unit.clone()).collect();
        units.sort();
        let changed: Vec<&str> = changed.iter().map(|c| c.dir()).collect();
        self.log.push(format!(
            "services {} changed {}",
            units.join(","),
            changed.join(",")
        ));
        self.running = units;
        Ok(())
    }

    fn unit_states(&mut self, units: &[String]) -> BTreeMap<String, String> {
        units
            .iter()
            .map(|u| {
                let s = if self.running.contains(u) {
                    "active"
                } else {
                    "inactive"
                };
                (u.clone(), s.to_string())
            })
            .collect()
    }
}

impl System for Box<dyn System> {
    fn nft_check(&mut self, body: &str, preserved: &[String]) -> Result<(), Error> {
        (**self).nft_check(body, preserved)
    }
    fn nft_load(&mut self, body: &str, preserved: &[String]) -> Result<Vec<String>, Error> {
        (**self).nft_load(body, preserved)
    }
    fn nft_chains(&mut self) -> Result<Option<Vec<String>>, Error> {
        (**self).nft_chains()
    }
    fn networkd_apply(&mut self, old: &Files, new: &Files, early: bool) -> Result<(), Error> {
        (**self).networkd_apply(old, new, early)
    }
    fn networkd_reconfigure(&mut self, links: &[String]) -> Result<(), Error> {
        (**self).networkd_reconfigure(links)
    }
    fn sysctl_apply(&mut self, content: &str) -> Result<(), Error> {
        (**self).sysctl_apply(content)
    }
    fn link_states(&mut self) -> BTreeMap<String, String> {
        (**self).link_states()
    }
    fn install_files(&mut self, sub: Subsystem, files: &Files) -> Result<(), Error> {
        (**self).install_files(sub, files)
    }
    fn service_check(&mut self, spec: &CheckSpec, files: &Files) -> Result<(), Error> {
        (**self).service_check(spec, files)
    }
    fn services_apply(&mut self, meta: &Meta, changed: &[Subsystem]) -> Result<(), Error> {
        (**self).services_apply(meta, changed)
    }
    fn unit_states(&mut self, units: &[String]) -> BTreeMap<String, String> {
        (**self).unit_states(units)
    }
}
