//! The web UI and HTTP API (`management.web`). `sparewall-httpd` has no
//! rendered files: the document only decides whether it runs. The
//! coordinator keeps the HTTPS port and passes it everything but the
//! health endpoints, over its socket.

use sparewall_config::model::Document;

use crate::{Rendered, Service, Subsystem};

pub const UNIT: &str = "sparewall-httpd.service";
/// Where `sparewall-httpd` listens (plain HTTP; TLS is the coordinator's).
pub const SOCKET: &str = "/run/sparewall-httpd/http.sock";

pub(crate) fn render(doc: &Document, out: &mut Rendered) {
    if !doc.management.web {
        return;
    }
    out.meta.services.insert(
        "web".into(),
        Service {
            provider: "sparewall-httpd".into(),
            unit: UNIT.into(),
            subsystem: Subsystem::Web,
            reload: false,
            management: true,
            check: None,
        },
    );
}
