//! A tiny builder for systemd-style INI files.

#[derive(Default)]
pub(crate) struct Ini {
    sections: Vec<(String, Vec<(String, String)>)>,
}

impl Ini {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Start a new section (sections may repeat, e.g. `[WireGuardPeer]`).
    pub(crate) fn section(&mut self, name: &str) -> &mut Self {
        self.sections.push((name.to_string(), Vec::new()));
        self
    }

    pub(crate) fn set(&mut self, key: &str, value: impl ToString) -> &mut Self {
        self.sections
            .last_mut()
            .expect("section before set")
            .1
            .push((key.to_string(), value.to_string()));
        self
    }

    pub(crate) fn opt<T: ToString>(&mut self, key: &str, value: Option<T>) -> &mut Self {
        if let Some(v) = value {
            self.set(key, v);
        }
        self
    }

    pub(crate) fn yes_no(&mut self, key: &str, value: Option<bool>) -> &mut Self {
        self.opt(key, value.map(|b| if b { "yes" } else { "no" }))
    }

    pub(crate) fn build(&self) -> String {
        let mut s = String::from(crate::HEADER);
        for (name, kvs) in &self.sections {
            if kvs.is_empty() && name != "Match" {
                continue;
            }
            s.push('\n');
            s.push_str(&format!("[{name}]\n"));
            for (k, v) in kvs {
                s.push_str(&format!("{k}={v}\n"));
            }
        }
        s
    }
}
