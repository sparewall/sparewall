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

    /// The members a bond holds now, each with whether its link is up
    /// (the bonding driver's MII status).
    fn bond_members(&mut self, bond: &str) -> Vec<(String, bool)>;

    /// Install a provider subsystem's files (under `/run/sparewall/<dir>`).
    fn install_files(&mut self, sub: Subsystem, files: &Files) -> Result<(), Error>;

    /// Dry-run rendered files with the daemon's own checker.
    fn service_check(&mut self, spec: &CheckSpec, files: &Files) -> Result<(), Error>;

    /// Start the services a generation needs, reload or restart those whose
    /// files changed, and stop the provider services it does not need.
    fn services_apply(&mut self, meta: &Meta, changed: &[Subsystem]) -> Result<(), Error>;

    /// `systemctl is-active` state of each unit.
    fn unit_states(&mut self, units: &[String]) -> BTreeMap<String, String>;

    /// The live `inet sparewall` table as `nft -j` JSON, for counters.
    fn nft_json(&mut self) -> Result<Option<serde_json::Value>, Error>;

    /// A kernel value under /proc/sys, e.g. `net/netfilter/nf_conntrack_count`.
    fn proc_sys(&mut self, key: &str) -> Option<String>;

    /// This node's sync-tunnel WireGuard public key, generating the key
    /// pair on first use. The private key never leaves the node.
    fn sync_public_key(&mut self) -> Result<String, Error>;

    /// Encrypt a secret for this node (`systemd-creds`, TPM2-bound where
    /// available).
    fn encrypt(&mut self, name: &str, plaintext: &[u8]) -> Result<Vec<u8>, Error>;

    /// Decrypt what [`System::encrypt`] produced on this node.
    fn decrypt(&mut self, name: &str, ciphertext: &[u8]) -> Result<Vec<u8>, Error>;

    /// A new WireGuard private key and its public key.
    fn wg_keypair(&mut self) -> Result<(String, String), Error>;

    /// The public key of a WireGuard private key.
    fn wg_public(&mut self, private: &str) -> Result<String, Error>;

    /// Make a secret available to a daemon in tmpfs (`/run/sparewall/keys`),
    /// readable by `group`.
    fn install_key(&mut self, file: &str, content: &[u8], group: &str) -> Result<(), Error>;

    /// Delete and recreate a netdev from its (unchanged) files.
    fn netdev_recreate(&mut self, name: &str) -> Result<(), Error>;
}

/// An injected failure's message, cleared after use with `once`.
fn injected(slot: &mut Option<String>, once: bool) -> Option<String> {
    if once { slot.take() } else { slot.clone() }
}

/// A recording fake for tests.
#[derive(Debug, Default)]
pub struct Fake {
    pub log: Vec<String>,
    pub nft_body: Option<String>,
    pub network: Files,
    pub sysctl: Option<String>,
    pub links: BTreeMap<String, String>,
    /// Members of each bond, with their MII status.
    pub bonds: BTreeMap<String, Vec<(String, bool)>>,
    /// Make `nft_check` fail with this message.
    pub fail_nft_check: Option<String>,
    /// Make `nft_load` fail with this message.
    pub fail_nft_load: Option<String>,
    /// Make `networkd_apply` fail with this message (after taking the
    /// files: a failure partway through changing links).
    pub fail_networkd_apply: Option<String>,
    /// Make `services_apply` fail with this message (a provider reload).
    pub fail_services_apply: Option<String>,
    /// Make `sysctl_apply` fail with this message.
    pub fail_sysctl_apply: Option<String>,
    /// Calls of `sysctl_apply` that succeed before `fail_sysctl_apply`
    /// fires (activation sets sysctls before and after the links).
    pub fail_sysctl_skip: usize,
    /// Make `install_files` (a provider's configuration) fail.
    pub fail_install_files: Option<String>,
    /// Injected failures (`fail_nft_load`, `fail_sysctl_apply`,
    /// `fail_networkd_apply`, `fail_install_files`, `fail_services_apply`)
    /// fire once, then clear.
    pub fail_once: bool,
    pub existing_sets: Vec<String>,
    /// Provider files installed, by subsystem.
    pub installed: BTreeMap<Subsystem, Files>,
    /// Make `service_check` fail with this message.
    pub fail_service_check: Option<String>,
    /// Units started by `services_apply`.
    pub running: Vec<String>,
    /// What `nft_json` returns (default: the loaded script, wrapped).
    pub nft_json: Option<serde_json::Value>,
    /// Make `nft_json` fail with this message.
    pub fail_nft_json: Option<String>,
    /// Make `nft_json` report no table.
    pub hide_nft_json: bool,
    /// What `proc_sys` returns, by key.
    pub proc: BTreeMap<String, String>,
    /// The sync public key `sync_public_key` reports.
    pub sync_key: Option<String>,
    /// WireGuard key pairs generated so far.
    pub keys_made: u32,
    /// Keys installed for daemons, by file name.
    pub runtime_keys: BTreeMap<String, Vec<u8>>,
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
        if let Some(m) = injected(&mut self.fail_nft_load, self.fail_once) {
            return Err(Error::Apply(m));
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
        match injected(&mut self.fail_networkd_apply, self.fail_once) {
            Some(m) => Err(Error::Apply(m)),
            None => Ok(()),
        }
    }

    fn networkd_reconfigure(&mut self, links: &[String]) -> Result<(), Error> {
        self.log.push(format!("reconfigure {}", links.join(",")));
        Ok(())
    }

    fn sysctl_apply(&mut self, content: &str) -> Result<(), Error> {
        self.log.push("sysctl".into());
        if self.fail_sysctl_apply.is_some() && self.fail_sysctl_skip > 0 {
            self.fail_sysctl_skip -= 1;
        } else if let Some(m) = injected(&mut self.fail_sysctl_apply, self.fail_once) {
            return Err(Error::Apply(m));
        }
        self.sysctl = Some(content.to_string());
        Ok(())
    }

    fn link_states(&mut self) -> BTreeMap<String, String> {
        self.links.clone()
    }

    fn bond_members(&mut self, bond: &str) -> Vec<(String, bool)> {
        self.bonds.get(bond).cloned().unwrap_or_default()
    }

    fn install_files(&mut self, sub: Subsystem, files: &Files) -> Result<(), Error> {
        self.log.push(format!("install {}", sub.dir()));
        if let Some(m) = injected(&mut self.fail_install_files, self.fail_once) {
            return Err(Error::Apply(m));
        }
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
        match injected(&mut self.fail_services_apply, self.fail_once) {
            Some(m) => Err(Error::Apply(m)),
            None => Ok(()),
        }
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

    fn nft_json(&mut self) -> Result<Option<serde_json::Value>, Error> {
        if let Some(m) = &self.fail_nft_json {
            return Err(Error::Apply(m.clone()));
        }
        if self.hide_nft_json {
            return Ok(None);
        }
        // The loaded script stands in for the kernel's listing, so a test
        // can tamper with `nft_body` to simulate drift.
        Ok(self.nft_json.clone().or_else(|| {
            self.nft_body.as_ref().map(|b| {
                serde_json::json!({"nftables": [
                    {"table": {"family": "inet", "name": "sparewall"}},
                    {"script": {"body": b}},
                ]})
            })
        }))
    }

    fn proc_sys(&mut self, key: &str) -> Option<String> {
        self.proc.get(key).cloned()
    }

    fn encrypt(&mut self, name: &str, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let mut v = format!("fake:{name}:").into_bytes();
        v.extend(plaintext.iter().map(|b| b ^ 0x5a));
        Ok(v)
    }

    fn decrypt(&mut self, name: &str, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let prefix = format!("fake:{name}:");
        let body = ciphertext
            .strip_prefix(prefix.as_bytes())
            .ok_or_else(|| Error::Apply(format!("secret {name}: wrong key")))?;
        Ok(body.iter().map(|b| b ^ 0x5a).collect())
    }

    fn wg_keypair(&mut self) -> Result<(String, String), Error> {
        self.keys_made += 1;
        let private = format!("{:0>43}=", format!("FakePrivateKey{}", self.keys_made));
        let public = self.wg_public(&private)?;
        Ok((private, public))
    }

    fn wg_public(&mut self, private: &str) -> Result<String, Error> {
        Ok(format!(
            "{:0>43}=",
            format!(
                "FakePublic{}",
                private.trim_start_matches('0').trim_end_matches('=')
            )
        ))
    }

    fn netdev_recreate(&mut self, name: &str) -> Result<(), Error> {
        self.log.push(format!("recreate {name}"));
        Ok(())
    }

    fn install_key(&mut self, file: &str, content: &[u8], _group: &str) -> Result<(), Error> {
        self.runtime_keys.insert(file.to_string(), content.to_vec());
        Ok(())
    }

    fn sync_public_key(&mut self) -> Result<String, Error> {
        Ok(self
            .sync_key
            .get_or_insert_with(|| "RmFrZVN5bmNLZXlGb3JUZXN0c0Zha2VTeW5jS2V5MTI=".into())
            .clone())
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
    fn bond_members(&mut self, bond: &str) -> Vec<(String, bool)> {
        (**self).bond_members(bond)
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
    fn nft_json(&mut self) -> Result<Option<serde_json::Value>, Error> {
        (**self).nft_json()
    }
    fn proc_sys(&mut self, key: &str) -> Option<String> {
        (**self).proc_sys(key)
    }
    fn sync_public_key(&mut self) -> Result<String, Error> {
        (**self).sync_public_key()
    }
    fn encrypt(&mut self, name: &str, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        (**self).encrypt(name, plaintext)
    }
    fn decrypt(&mut self, name: &str, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        (**self).decrypt(name, ciphertext)
    }
    fn wg_keypair(&mut self) -> Result<(String, String), Error> {
        (**self).wg_keypair()
    }
    fn wg_public(&mut self, private: &str) -> Result<String, Error> {
        (**self).wg_public(private)
    }
    fn install_key(&mut self, file: &str, content: &[u8], group: &str) -> Result<(), Error> {
        (**self).install_key(file, content, group)
    }
    fn netdev_recreate(&mut self, name: &str) -> Result<(), Error> {
        (**self).netdev_recreate(name)
    }
}
