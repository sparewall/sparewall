//! sshd: whether the admin password is accepted over SSH as well as keys
//! (`management.ssh.password`). The image's sshd drop-in includes this
//! file before its own `PasswordAuthentication no`, and sshd keeps the
//! first value it reads. It is rendered either way, bootstrap included,
//! so that turning it off, or a revert, reloads sshd too.

use sparewall_config::model::Document;

use crate::{Rendered, Service, Subsystem};

pub const UNIT: &str = "sshd.service";
pub const CONF: &str = "sparewall.conf";

fn add(out: &mut Rendered, password: bool) {
    let yes = if password { "yes" } else { "no" };
    out.add(
        Subsystem::Ssh,
        CONF,
        format!("{}PasswordAuthentication {yes}\n", crate::HEADER),
    );
    out.meta.services.insert(
        "ssh".into(),
        Service {
            provider: "openssh".into(),
            unit: UNIT.into(),
            subsystem: Subsystem::Ssh,
            reload: true,
            check: None,
        },
    );
}

pub(crate) fn render(doc: &Document, out: &mut Rendered) {
    add(out, doc.management.ssh.password);
}

pub(crate) fn render_bootstrap(out: &mut Rendered) {
    add(out, false);
}
