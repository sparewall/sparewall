// Generated from docs/api/openapi.json by scripts/api-types.mjs; do not edit.
// Regenerate with `npm run api`.

/** The description's named types. */
export interface Schemas {
  /** A whole deployment: one node or an HA pair. */
  "Document": {
    /** Scheduled backups of the node bundle. */
    "backup"?: Schemas["Document.Backup"] | null;
    /** Node names and pair-wide settings. */
    "cluster": Schemas["Document.Cluster"];
    /** DHCPv4 service per network. */
    "dhcp"?: Schemas["Document.Dhcp"] | null;
    /** Recursive DNS for the served networks. */
    "dns"?: Schemas["Document.Dns"] | null;
    /** Inbound port forwards (DNAT). */
    "forwards"?: Record<string, Schemas["Document.Forward"]>;
    /** Rule-log defaults and remote forwarding. */
    "logging"?: Schemas["Document.Logging"] | null;
    /** Which network is management, and the anti-lockout switch. */
    "management": Schemas["Document.Management"];
    /** Metrics collection. */
    "metrics"?: Schemas["Document.Metrics"] | null;
    /** Layer-2 segments, keyed by network name (also the interface name). */
    "networks"?: Record<string, Schemas["Document.Network"]>;
    /** Time service. */
    "ntp"?: Schemas["Document.Ntp"] | null;
    /** Named address and port sets, referenced from rules as `@name`. */
    "objects"?: Record<string, Schemas["Document.Object"]>;
    /** Zone-pair policies keyed by `"from->to"`. */
    "policy"?: Record<string, Schemas["Document.Policy"]>;
    /** Per node: port role name to the hardware it is bound to. */
    "ports"?: Record<string, Record<string, Schemas["Document.Port"]>>;
    /** Per-provider passthrough settings, keyed by provider name. Not
     * built yet: any entry is rejected. */
    "provider_options"?: Record<string, unknown>;
    /** Raw nft statements placed at named hook points. */
    "raw"?: Record<string, Schemas["Document.RawEntry"]>;
    /** Schema version of this document. */
    "schema": number;
    /** Certificates. */
    "tls"?: Schemas["Document.Tls"] | null;
    /** OS image update policy. */
    "updates"?: Schemas["Document.Updates"] | null;
    /** Remote-access WireGuard instances. */
    "vpn"?: Record<string, Schemas["Document.Vpn"]>;
    /** Named groups of networks. `self` is built in and cannot be defined. */
    "zones"?: Record<string, Schemas["Document.Zone"]>;
  };
  "Document.Acme": {
    /** PEM of the CA that signs the directory's TLS certificate, for a
     * private CA (default: the system trust store). */
    "ca"?: string | null;
    /** `dns-01` (default) or `http-01`. */
    "challenge"?: string | null;
    "directory": string;
    "dns"?: Schemas["Document.AcmeDns"] | null;
    /** External Account Binding key ID and secret reference. */
    "eab"?: Schemas["Document.Eab"] | null;
    "email"?: string | null;
  };
  "Document.AcmeDns": {
    /** Secret reference, `secret:<name>`. For `rfc2136`, the TSIG key as
     * `algorithm:name:secret`; for lego, the provider's credentials as
     * `KEY=value` lines. */
    "credentials"?: string | null;
    /** For `rfc2136`, `server` (host[:port]) and `zone`; for lego, the
     * provider's other environment variables (`GCE_PROJECT`), and lego's
     * own (`LEGO_DNS_RESOLVERS`). */
    "options"?: Record<string, string>;
    /** `rfc2136` (built in), or a lego provider code such as `gcloud`,
     * `cloudflare` or `route53` (https://go-acme.github.io/lego/dns/). */
    "provider": string;
  };
  "Document.Action": "accept" | "drop" | "reject";
  "Document.Backup": {
    /** Secret reference for repository credentials (not the password). */
    "credentials"?: string | null;
    "enabled": boolean;
    /** Generations to include. Default 20. */
    "generations"?: number | null;
    /** restic repository URL. */
    "repository"?: string | null;
    /** systemd calendar expression. Default `hourly`. */
    "schedule"?: string | null;
  };
  "Document.Bond": {
    /** Transmit hash policy, e.g. `layer3+4`. */
    "hash_policy"?: string | null;
    /** LACP rate (802.3ad only). */
    "lacp_rate"?: Schemas["Document.LacpRate"] | null;
    /** Member NICs, each a permanent MAC address or udev path. */
    "members": Array<string>;
    /** Link monitoring interval, e.g. `100ms`. */
    "miimon"?: string | null;
    /** Bonding mode. */
    "mode": Schemas["Document.BondMode"];
    /** Preferred member (active-backup only). */
    "primary"?: string | null;
  };
  "Document.BondMode": "802.3ad" | "active-backup";
  "Document.Cake": {
    /** Egress bandwidth, e.g. `900mbit`. */
    "bandwidth": string;
  };
  "Document.Certificate": {
    "acme"?: Schemas["Document.Acme"] | null;
    "names": Array<string>;
  };
  /** IPv4 address with prefix length, e.g. 192.0.2.1/24 */
  "Document.Cidr": string;
  "Document.Cluster": {
    /** Connection-tracking sizing, identical on both nodes. */
    "conntrack"?: Schemas["Document.ConntrackSizing"] | null;
    /** Stage beside the gateway this replaces: everything runs, but no
     * gateway address is claimed (VRRP instances held in FAULT, or not
     * installed standalone) and DHCP offers nothing. Set false to cut over. */
    "hold"?: boolean;
    /** One node name (standalone) or two (an HA pair). Each is also that
     * node's hostname: up to 31 lowercase letters, digits and '-',
     * starting with a letter and not ending with '-'. */
    "nodes": Array<string>;
    /** Each node's sync-tunnel WireGuard public key, from `sparewall status`. */
    "sync_keys"?: Record<string, string>;
    /** The network with role `sync` that carries the pair's WireGuard tunnel. */
    "sync_network"?: string | null;
    /** UDP port of the sync tunnel. */
    "sync_port"?: number | null;
    /** VRRP settings for a pair. */
    "vrrp"?: Schemas["Document.Vrrp"] | null;
  };
  "Document.ConntrackSizing": {
    /** Hash table buckets (`nf_conntrack_buckets`). */
    "buckets"?: number | null;
    /** `nf_conntrack_max`. */
    "max"?: number | null;
    /** Established-TCP timeout in seconds. Default 86400. */
    "tcp_established_timeout"?: number | null;
  };
  /** DHCPv4: service-wide settings plus one entry per served network. */
  "Document.Dhcp": {
    /** HA mode for a pair. Default `hot-standby`. */
    "ha"?: Schemas["Document.DhcpHa"] | null;
    /** Default lease time in seconds. */
    "lease_time"?: number | null;
    /** Ping an address before offering it, and skip it if something
     * answers: a host still using it without a lease here (after a
     * restore, or when replacing another DHCP server). Default true; turn
     * it off on networks that filter ICMP echo. */
    "ping_check"?: boolean | null;
    /** Implementation: `kea` (the default). `networkd` is not built yet. */
    "provider"?: string | null;
    [key: string]: unknown;
  };
  "Document.DhcpHa": "hot-standby" | "off";
  "Document.DhcpNetwork": {
    /** Lease time in seconds for this network. */
    "lease_time"?: number | null;
    /** Options; router, DNS and NTP default to the gateway address. */
    "options"?: Schemas["Document.DhcpOptions"] | null;
    /** Ping before offering on this network (default: `dhcp.ping_check`). */
    "ping_check"?: boolean | null;
    /** Address range, `first-last`. */
    "pool": string;
    /** Fixed leases by name. */
    "reservations"?: Record<string, Schemas["Document.Reservation"]>;
  };
  "Document.DhcpOptions": {
    "dns"?: Array<string>;
    "domain"?: string | null;
    "ntp"?: Array<string>;
    "router"?: string | null;
  };
  "Document.Dns": {
    /** Local domain for reservation names. */
    "domain"?: string | null;
    "enabled": boolean;
    /** Forward to these servers instead of recursing. */
    "forwarders"?: Array<string>;
    /** Networks to serve; default every network with DHCP. */
    "networks"?: Array<string>;
    /** Implementation: `unbound` (the default). */
    "provider"?: string | null;
    /** Extra local A records, name to address. */
    "records"?: Record<string, string>;
  };
  "Document.DynamicKind": "address" | "prefix";
  "Document.DynamicSource": {
    /** The network whose addresses fill the set. */
    "network": string;
    /** `address` for the node's own address, `prefix` for the subnet. */
    "source"?: Schemas["Document.DynamicKind"];
  };
  "Document.Eab": {
    "hmac": string;
    "kid": string;
  };
  /** An inbound port forward. */
  "Document.Forward": {
    /** Port(s) on the firewall. */
    "dport": Schemas["Document.Match"];
    /** Original destination; default any address of the arriving zone. */
    "dst"?: Schemas["Document.Match"] | null;
    /** Zone the connections arrive from. Default `wan`. */
    "from"?: string | null;
    /** Inside zones whose clients may also use the forward by its outside
     * address (NAT reflection), e.g. `[users]`. Needs `dst`. Clients on
     * the server's own network are also source-NATed to the firewall's
     * address there, so that replies come back through it. */
    "hairpin"?: Array<string>;
    /** Log forwarded connections. */
    "log"?: boolean;
    /** `tcp` or `udp`. */
    "proto": string;
    /** Allowed sources. */
    "src"?: Schemas["Document.Match"] | null;
    /** Internal address to forward to. */
    "to": string;
    /** Internal port; default unchanged. */
    "to_port"?: number | null;
  };
  "Document.LacpRate": "slow" | "fast";
  "Document.Logging": {
    /** Record connection start/end with NAT mappings. */
    "connections"?: boolean;
    /** nflog group used for rule logging. Default 0. */
    "group"?: number | null;
    "remote"?: Schemas["Document.RemoteLog"] | null;
  };
  "Document.Management": {
    /** Always accept SSH and HTTPS from the management network to `self`.
     * Only an `admin` may turn this off. */
    "anti_lockout"?: boolean;
    /** The network with role `management`. */
    "network": string;
    /** SSH to the node. */
    "ssh"?: Schemas["Document.ManagementSsh"];
    /** Serve the web UI and the HTTP API (`sparewall-httpd`) on the HTTPS
     * port, next to the health endpoints. Off by default; reached only
     * where HTTPS is, the management network. */
    "web"?: boolean;
  };
  "Document.ManagementSsh": {
    /** Also accept the `admin` password (`sparewall passwd`) over SSH, not
     * only keys. Off by default: the password is the console's
     * break-glass path. */
    "password"?: boolean;
  };
  /** A match value: a scalar, a list, or an `@object` reference. */
  "Document.Match": number | string | Array<Schemas["Document.MatchItem"]>;
  "Document.MatchItem": number | string;
  "Document.Metrics": {
    /** `external`: `/metrics` answers the management network without a
     * token, for an external Prometheus. `off`: not served. (Without a
     * `metrics` section it needs a token.) `local` (a local Prometheus)
     * is not built yet and is rejected. */
    "mode": Schemas["Document.MetricsMode"];
    /** Local Prometheus retention, e.g. `15d`. Not built yet, with the
     * local mode: rejected. */
    "retention"?: string | null;
  };
  "Document.MetricsMode": "external" | "local" | "off";
  "Document.Nat": Schemas["Document.NatMode"] | {
    "snat": string;
  };
  "Document.NatMode": "masquerade";
  /** One layer-2 segment. */
  "Document.Network": {
    /** Each node's own address on this network, in CIDR form. */
    "addresses"?: Record<string, Schemas["Document.Cidr"]>;
    /** WAN shaping with CAKE, e.g. `{ egress: 900mbit }`. */
    "cake"?: Schemas["Document.Cake"] | null;
    /** Obtain this node's address by DHCP (WAN or management only). */
    "dhcp_client"?: boolean;
    /** Upstream DNS servers learned statically on this network. */
    "dns"?: Array<string>;
    /** More addresses that move with the gateway address (in its VRRP
     * instance in a pair; static standalone), for forwards and SNAT, e.g.
     * a mail server's public address. In the gateway address's subnet. */
    "extra_vips"?: Array<Schemas["Document.Cidr"]>;
    /** Upstream gateway (default route) for a static WAN or a management
     * network with its own upstream. */
    "gateway"?: string | null;
    /** Emit and receive LLDP on this network. Default true on untagged ports. */
    "lldp"?: boolean | null;
    /** MTU of this network's interface. */
    "mtu"?: number | null;
    /** The port role this network rides on. */
    "port": string;
    /** What the network is for. Default `service`. */
    "role"?: Schemas["Document.NetworkRole"];
    /** The gateway address clients use. Moved by VRRP in a pair, a plain
     * static address on a standalone node. */
    "vip"?: Schemas["Document.Cidr"] | null;
    /** 802.1Q VLAN ID; omit for the untagged network of a port. */
    "vlan"?: number | null;
    /** VRRP virtual router ID (1-255), unique across the deployment. */
    "vrid"?: number | null;
  };
  "Document.NetworkRole": "service" | "wan" | "management" | "sync";
  "Document.Ntp": {
    /** Networks to serve time on. */
    "serve"?: Array<string>;
    /** Upstream servers or pools. */
    "servers"?: Array<string>;
  };
  /** A named set: static elements, or a dynamic set filled by networkd. */
  "Document.Object": {
    /** Fill from a network's addresses instead (`ipv4` only). */
    "dynamic"?: Schemas["Document.DynamicSource"] | null;
    /** Static elements: addresses or prefixes for `ipv4`, ports or ranges for
     * `port`. */
    "elements"?: Array<Schemas["Document.MatchItem"]>;
    /** Element type. */
    "type": Schemas["Document.ObjectKind"];
  };
  "Document.ObjectKind": "ipv4" | "port";
  "Document.Offload": {
    "gro"?: boolean | null;
    "gso"?: boolean | null;
    "rx_checksum"?: boolean | null;
    "tso"?: boolean | null;
    "tx_checksum"?: boolean | null;
  };
  /** Policy for traffic from one zone to another. */
  "Document.Policy": {
    /** What happens to traffic no rule matched. */
    "action": Schemas["Document.Action"];
    /** Log traffic that reaches the default action. */
    "log"?: boolean;
    /** Source NAT applied to this zone pair. */
    "nat"?: Schemas["Document.Nat"] | null;
    /** Named rules, evaluated by ascending `order`. */
    "rules"?: Record<string, Schemas["Document.Rule"]>;
  };
  /** What a port role is bound to on one node. */
  "Document.Port": {
    /** A bond of several NICs. */
    "bond"?: Schemas["Document.Bond"] | null;
    /** MTU of the port (VLAN networks may set their own, no larger). */
    "mtu"?: number | null;
    /** One NIC, matched by permanent MAC address (`52:54:00:aa:00:01`) or by
     * udev path (`pci-0000:01:00.0`). */
    "nic"?: string | null;
    /** NIC offload overrides for misbehaving drivers. */
    "offload"?: Schemas["Document.Offload"] | null;
  };
  "Document.RawAt": {
    /** Zone pair, `"from->to"`. */
    "pair": string;
    "position": Schemas["Document.RawPosition"];
  } | {
    "hook": Schemas["Document.RawHook"];
  };
  /** A raw nft statement placed at a hook point. */
  "Document.RawEntry": {
    /** Where the statement goes. */
    "at": Schemas["Document.RawAt"];
    /** The nft statement, without a trailing comment. */
    "nft": string;
    /** Position among raw entries at the same point. */
    "order": number;
  };
  "Document.RawHook": "prerouting-raw" | "forward" | "input" | "postrouting";
  "Document.RawPosition": "before" | "after";
  "Document.RemoteLog": {
    /** URL or `host:port`. */
    "destination": string;
    /** `udp`, `tcp`, `relp` (syslog only). */
    "protocol"?: string | null;
    /** `journal-upload` (the default). `syslog` is not built yet. */
    "provider"?: string | null;
    "tls"?: boolean;
  };
  "Document.Reservation": {
    "address": string;
    /** Hostname to hand out (and publish in local DNS). */
    "hostname"?: string | null;
    "mac": string;
  };
  "Document.Rule": {
    /** What to do with matching packets. */
    "action": Schemas["Document.Action"];
    /** Free-form note, not rendered. */
    "comment"?: string | null;
    /** Destination port(s): a number, `low-high`, a list, or `@object`. */
    "dport"?: Schemas["Document.Match"] | null;
    /** Destination: an address, a prefix, a list of them, or `@object`. */
    "dst"?: Schemas["Document.Match"] | null;
    /** ICMP type names, e.g. `echo-request` (proto `icmp`). */
    "icmp_type"?: Array<string>;
    /** Rate limit, e.g. `10/second` or `100/minute burst 20`. */
    "limit"?: string | null;
    /** Log matching packets. */
    "log"?: boolean;
    /** Position within the zone pair; leave gaps (100, 200, ...). */
    "order": number;
    /** `tcp`, `udp`, `icmp` or another protocol name nft knows. */
    "proto"?: string | null;
    /** Source port(s): a number, `low-high`, a list, or `@object`. */
    "sport"?: Schemas["Document.Match"] | null;
    /** Source: an address, a prefix, a list of them, or `@object`. */
    "src"?: Schemas["Document.Match"] | null;
  };
  "Document.Tls": {
    "certificates"?: Record<string, Schemas["Document.Certificate"]>;
  };
  "Document.UpdateMode": "manual" | "windowed";
  "Document.Updates": {
    /** `stable` or `testing`. */
    "channel"?: string | null;
    /** `manual` (the default): upgrades run when asked for, with
     * `sparewall upgrade`. `windowed` (automatic upgrades in `window`) is
     * not built yet and is rejected. */
    "mode"?: Schemas["Document.UpdateMode"] | null;
    /** Maintenance window as a systemd calendar expression. Not built yet,
     * with the windowed mode: rejected. */
    "window"?: string | null;
  };
  "Document.Vpn": {
    /** Tunnel addresses of the firewall. */
    "addresses": Array<Schemas["Document.Cidr"]>;
    /** Networks routed through the tunnel in client configs; default all. */
    "client_allowed_ips"?: Array<string>;
    /** DNS servers pushed in client configs. */
    "dns"?: Array<string>;
    /** Public name or address clients connect to. */
    "endpoint": string;
    /** More UDP ports clients may use from networks that block the listen
     * port, e.g. `[53, 443]`: redirected to it on the WAN gateway address. */
    "extra_ports"?: Array<number>;
    "listen_port": number;
    "peers"?: Record<string, Schemas["Document.VpnPeer"]>;
    /** The zone the tunnel interface belongs to. */
    "zone": string;
  };
  "Document.VpnPeer": {
    "addresses": Array<Schemas["Document.Cidr"]>;
    /** Static endpoint, for site-to-site peers. */
    "endpoint"?: string | null;
    /** WireGuard preshared key, a cluster secret: `secret:<name>`. The
     * client must be configured with the same key (`wg genpsk`). */
    "preshared_key"?: string | null;
    "public_key": string;
  };
  "Document.Vrrp": {
    /** Advertisement interval in centiseconds (VRRPv3). Default 100 (1 s). */
    "advert_interval_cs"?: number | null;
    /** Fail back by itself: the node with the higher priority takes the
     * gateway addresses back once it has been up and eligible for this
     * many seconds (1-1000). Unset (the default), the pair never
     * preempts, so it cannot bounce while that node flaps; move the
     * addresses with `sparewall failover` instead. The delay is then the
     * only protection against flapping. */
    "preempt_delay_s"?: number | null;
    /** VRRP priority per node; give the larger node the higher value. */
    "priority"?: Record<string, number>;
    /** Send adverts unicast to the peer instead of multicast. */
    "unicast"?: boolean | null;
    /** Use VRRP virtual MAC addresses. */
    "use_vmac"?: boolean | null;
  };
  "Document.Zone": {
    /** Member networks. */
    "networks"?: Array<string>;
  };
  /** A Varlink error: its name and parameters, and a message in words. The HTTP status follows the error (422 ValidationFailed, 409 Conflict, NotPending and ConfirmTimeout, 401 PermissionDenied without credentials and 403 with them, 404 NotFound, MethodNotFound and InterfaceNotFound, 503 PeerUnreachable, 400 NotSupported, InvalidParameter and malformed calls, 500 the rest; the gateway's own: 502 Unavailable, 404 NotFound, 405 MethodNotAllowed, 413 TooLarge). */
  "Error": {
    "error": "org.sparewall.Firewall.ApplyFailed";
    "message"?: string;
    "parameters": {
      "message": string;
    };
  } | {
    "error": "org.sparewall.Firewall.ConfirmTimeout";
    "message"?: string;
    "parameters": {
      "rolled_back_to": number;
    };
  } | {
    "error": "org.sparewall.Firewall.Conflict";
    "message"?: string;
    "parameters": {
      "current": number;
    };
  } | {
    "error": "org.sparewall.Firewall.NotFound";
    "message"?: string;
    "parameters": {
      "id": number;
    };
  } | {
    "error": "org.sparewall.Firewall.NotPending";
    "message"?: string;
    "parameters": {
      "id": number;
    };
  } | {
    "error": "org.sparewall.Firewall.NotSupported";
    "message"?: string;
    "parameters": {
      "message": string;
    };
  } | {
    "error": "org.sparewall.Firewall.PeerUnreachable";
    "message"?: string;
    "parameters": {
      "peer": string;
    };
  } | {
    "error": "org.sparewall.Firewall.PermissionDenied";
    "message"?: string;
    /** `role` is `none` on a connection not bound to a token. */
    "parameters": {
      "reason"?: string | null;
      "role": string;
    };
  } | {
    "error": "org.sparewall.Firewall.ValidationFailed";
    "message"?: string;
    "parameters": {
      "errors": Array<string>;
    };
  } | {
    "error": "org.sparewall.Httpd.MethodNotAllowed";
    "message"?: string;
    /** Calls are POST; files are GET. */
    "parameters": Record<string, unknown>;
  } | {
    "error": "org.sparewall.Httpd.NotFound";
    "message"?: string;
    /** No call or file has this path. */
    "parameters": Record<string, unknown>;
  } | {
    "error": "org.sparewall.Httpd.TooLarge";
    "message"?: string;
    /** The request body is over the gateway's limit. */
    "parameters": Record<string, unknown>;
  } | {
    "error": "org.sparewall.Httpd.Unavailable";
    "message"?: string;
    /** The coordinator did not answer the gateway. */
    "parameters": Record<string, unknown>;
  } | {
    "error": "org.varlink.service.ExpectedMore";
    "message"?: string;
    /** Method is expected to be called with 'more' set to true, but wasn't. */
    "parameters": Record<string, never>;
  } | {
    "error": "org.varlink.service.InterfaceNotFound";
    "message"?: string;
    /** The requested interface was not found. */
    "parameters": {
      /** The interface that was not found. */
      "interface": string;
    };
  } | {
    "error": "org.varlink.service.InvalidParameter";
    "message"?: string;
    /** One of the passed parameters is invalid. */
    "parameters": {
      /** The parameter that is invalid. */
      "parameter": string;
    };
  } | {
    "error": "org.varlink.service.MethodNotFound";
    "message"?: string;
    /** The requested method was not found. */
    "parameters": {
      /** The method that was not found. */
      "method": string;
    };
  } | {
    "error": "org.varlink.service.MethodNotImplemented";
    "message"?: string;
    /** The interface defines the requested method, but the service does not implement it. */
    "parameters": {
      /** The method that is not implemented. */
      "method": string;
    };
  } | {
    "error": "org.varlink.service.PermissionDenied";
    "message"?: string;
    /** Client is denied access. */
    "parameters": Record<string, never>;
  };
  "org.sparewall.Auth.TokenInfo": {
    "created": string;
    /** Unix time it expires, if ever. */
    "expires"?: number | null;
    "last_used"?: string | null;
    "name": string;
    /** `monitor`, `viewer`, `operator` or `admin`. */
    "role": string;
  };
  /** A named user (design: "Browser authentication"). */
  "org.sparewall.Auth.UserInfo": {
    /** No password: the user cannot log in. */
    "locked": boolean;
    "name": string;
    "role": string;
    "updated": string;
  };
  /** One configuration generation. */
  "org.sparewall.Firewall.Generation": {
    /** When it was created (RFC 3339). */
    "applied": string;
    "author": string;
    "base"?: number | null;
    /** False while it waits for `Confirm`. */
    "confirmed": boolean;
    /** SHA-256 of the canonical document (empty for bootstrap). */
    "hash": string;
    "id": number;
    "schema": number;
    /** One line per changed path. */
    "summary": Array<string>;
  };
  "org.sparewall.Firewall.HealthCheck": {
    "level": string;
    "message": string;
    "name": string;
  };
  "org.sparewall.Secrets.SecretInfo": {
    /** `node` or `cluster`. */
    "class": string;
    "name": string;
    "updated": string;
    "version": number;
  };
}

/** An error reply: its name, its parameters and a message in words. */
export type ApiError = Schemas['Error'];

/** Each call: its parameters, its reply, the role it needs, and whether it streams. */
export interface Calls {
  /** Bind this connection to a token (an API token or a session's): later calls act with its role. Needed first on the restricted socket. */
  "org.sparewall.Auth.Bind": {
    parameters: {
      "token": string;
    };
    reply: {
      /** The token's name. */
      "name": string;
      "role": string;
    };
    role: "none";
    streams: false;
  };
  /** Create an API token with `role`, expiring after `expires_days` if given. The token is shown once. */
  "org.sparewall.Auth.CreateToken": {
    parameters: {
      "expires_days"?: number | null;
      "name": string;
      "role": string;
    };
    reply: {
      "info": Schemas["org.sparewall.Auth.TokenInfo"];
      /** Shown once; only its hash is kept. */
      "token": string;
    };
    role: "admin";
    streams: false;
  };
  /** API tokens (never their values). */
  "org.sparewall.Auth.ListTokens": {
    parameters: Record<string, never>;
    reply: {
      "tokens": Array<Schemas["org.sparewall.Auth.TokenInfo"]>;
    };
    role: "admin";
    streams: false;
  };
  /** Users and their roles, `admin` first. */
  "org.sparewall.Auth.ListUsers": {
    parameters: Record<string, never>;
    reply: {
      "users": Array<Schemas["org.sparewall.Auth.UserInfo"]>;
    };
    role: "admin";
    streams: false;
  };
  /** Check a user's password and open a session of 12 hours; the connection is bound to it. Failed logins are rate-limited per user. */
  "org.sparewall.Auth.Login": {
    parameters: {
      "password": string;
      "user": string;
    };
    reply: {
      /** Unix time the session ends. */
      "expires": number;
      "role": string;
      /** The session token, shown once. */
      "token": string;
      "user": string;
    };
    role: "none";
    streams: false;
  };
  /** End the session this connection is bound to. */
  "org.sparewall.Auth.Logout": {
    parameters: Record<string, never>;
    reply: Record<string, never>;
    role: "monitor";
    streams: false;
  };
  /** Remove a user and end its sessions. */
  "org.sparewall.Auth.RemoveUser": {
    parameters: {
      "name": string;
    };
    reply: Record<string, never>;
    role: "admin";
    streams: false;
  };
  /** Revoke an API token at once. */
  "org.sparewall.Auth.RevokeToken": {
    parameters: {
      "name": string;
    };
    reply: Record<string, never>;
    role: "admin";
    streams: false;
  };
  /** Add a user, or change its role or password (a crypt(3) hash; `!` locks it, empty keeps it). Ends the user's sessions. */
  "org.sparewall.Auth.SetUser": {
    parameters: {
      "name": string;
      "password_hash": string;
      "role": string;
    };
    reply: Record<string, never>;
    role: "admin";
    streams: false;
  };
  /** Move a pair's gateway addresses to `to` (default: the node with the higher VRRP priority). Returns when the move is done, or why it did not happen. */
  "org.sparewall.Cluster.Failover": {
    parameters: {
      "to"?: string | null;
    };
    reply: {
      /** The node that holds the gateway addresses now. */
      "master": string;
      /** What happened, in words. */
      "message": string;
    };
    role: "operator";
    streams: false;
  };
  /** Acknowledge a check that stays degraded until someone has seen it (`selinux`). */
  "org.sparewall.Firewall.AckHealth": {
    parameters: {
      "name": string;
    };
    reply: Record<string, never>;
    role: "admin";
    streams: false;
  };
  /** Replace the configuration with `config`. `base` is the generation it was derived from: Conflict if another change landed meanwhile. With `confirm_seconds`, the change reverts unless confirmed (`Confirm`) in time. `dry_run` validates, renders and checks it without running it. In a pair the peer must be reachable, or `allow_diverge` set. */
  "org.sparewall.Firewall.Apply": {
    parameters: {
      "allow_diverge"?: boolean | null;
      "base": number;
      "config": Schemas["Document"];
      "confirm_seconds"?: number | null;
      "dry_run"?: boolean | null;
    };
    reply: {
      /** Subsystems whose configuration changed. */
      "changed": Array<string>;
      /** Seconds until an unconfirmed generation reverts (0 if confirmed). */
      "confirm_seconds": number;
      /** One line per changed document path. */
      "diff": Array<string>;
      "generation": Schemas["org.sparewall.Firewall.Generation"];
      /** The document was identical to the active one. */
      "unchanged": boolean;
      "warnings": Array<string>;
    };
    role: "operator";
    streams: false;
  };
  /** Write a backup bundle now, and send it to `backup.repository` if one is set. */
  "org.sparewall.Firewall.Backup": {
    parameters: Record<string, never>;
    reply: {
      "digest": string;
      "path": string;
      /** Cluster secrets sealed in the bundle (none without a backup password). */
      "secrets": Array<string>;
      /** The restic snapshot, when sent to `backup.repository`. */
      "snapshot"?: string | null;
    };
    role: "admin";
    streams: false;
  };
  /** Keep generation `id`, which waits for confirmation. */
  "org.sparewall.Firewall.Confirm": {
    parameters: {
      "id": number;
    };
    reply: Record<string, never>;
    role: "operator";
    streams: false;
  };
  /** A generation's document alone (default: the active one). */
  "org.sparewall.Firewall.Export": {
    parameters: {
      "id"?: number | null;
    };
    reply: {
      "config": Schemas["Document"];
    };
    role: "viewer";
    streams: false;
  };
  /** A generation's document and record (default: the active one). */
  "org.sparewall.Firewall.GetConfig": {
    parameters: {
      "id"?: number | null;
    };
    reply: {
      "config": Schemas["Document"];
      "generation": Schemas["org.sparewall.Firewall.Generation"];
    };
    role: "viewer";
    streams: false;
  };
  /** This node's health level and VRRP role; with `verbose`, each check. */
  "org.sparewall.Firewall.Health": {
    parameters: {
      "verbose"?: boolean | null;
    };
    reply: {
      "checks"?: Array<Schemas["org.sparewall.Firewall.HealthCheck"]> | null;
      /** `ok`, `degraded` or `failed`. */
      "level": string;
      /** `standalone`, `bootstrap`, `MASTER` or `BACKUP`. */
      "role": string;
    };
    role: "monitor";
    streams: false;
  };
  /** Generations, newest first, up to `limit`. */
  "org.sparewall.Firewall.History": {
    parameters: {
      "limit"?: number | null;
    };
    reply: {
      "generations": Array<Schemas["org.sparewall.Firewall.Generation"]>;
    };
    role: "viewer";
    streams: false;
  };
  /** Change the configuration with a JSON merge patch (RFC 7396) on generation `base`, as `Apply` does. */
  "org.sparewall.Firewall.Merge": {
    parameters: {
      "allow_diverge"?: boolean | null;
      "base": number;
      "confirm_seconds"?: number | null;
      "dry_run"?: boolean | null;
      "patch": Record<string, unknown>;
    };
    reply: {
      /** Subsystems whose configuration changed. */
      "changed": Array<string>;
      /** Seconds until an unconfirmed generation reverts (0 if confirmed). */
      "confirm_seconds": number;
      /** One line per changed document path. */
      "diff": Array<string>;
      "generation": Schemas["org.sparewall.Firewall.Generation"];
      /** The document was identical to the active one. */
      "unchanged": boolean;
      "warnings": Array<string>;
    };
    role: "operator";
    streams: false;
  };
  /** Change the configuration with a JSON patch (RFC 6902) on generation `base`, as `Apply` does. */
  "org.sparewall.Firewall.Patch": {
    parameters: {
      "allow_diverge"?: boolean | null;
      "base": number;
      "confirm_seconds"?: number | null;
      "dry_run"?: boolean | null;
      "ops": Record<string, unknown>;
    };
    reply: {
      /** Subsystems whose configuration changed. */
      "changed": Array<string>;
      /** Seconds until an unconfirmed generation reverts (0 if confirmed). */
      "confirm_seconds": number;
      /** One line per changed document path. */
      "diff": Array<string>;
      "generation": Schemas["org.sparewall.Firewall.Generation"];
      /** The document was identical to the active one. */
      "unchanged": boolean;
      "warnings": Array<string>;
    };
    role: "operator";
    streams: false;
  };
  /** Return to generation `id` (default: the one before the active one) as a new generation; an unconfirmed change is discarded instead. */
  "org.sparewall.Firewall.Rollback": {
    parameters: {
      "allow_diverge"?: boolean | null;
      "id"?: number | null;
    };
    reply: {
      "generation": Schemas["org.sparewall.Firewall.Generation"];
    };
    role: "operator";
    streams: false;
  };
  /** The node's state: generations and hashes, pair sync, links, VRRP, connection tracking, the certificate it serves, and health. */
  "org.sparewall.Firewall.Status": {
    parameters: Record<string, never>;
    reply: {
      "conntrack": Record<string, unknown>;
      "health": Record<string, unknown>;
      "links": Record<string, unknown>;
      "node": string;
      "role": string;
      "services": Record<string, unknown>;
      /** Active generation, pending confirmation, hashes. */
      "sync": Record<string, unknown>;
      /** The certificate served on the management network. */
      "tls": Record<string, unknown>;
      "vrrp": Record<string, unknown>;
    };
    role: "viewer";
    streams: false;
  };
  /** Events as they happen: applied and rolled-back generations, peer and health changes, upgrade steps. The first reply confirms the subscription. */
  "org.sparewall.Firewall.Subscribe": {
    parameters: Record<string, never>;
    reply: {
      "event": Record<string, unknown>;
    };
    role: "viewer";
    streams: true;
  };
  /** In a pair, make both nodes run the configuration of `from_node`: this node (push it to the peer) or the peer (take the peer's). */
  "org.sparewall.Firewall.Sync": {
    parameters: {
      "from_node": string;
    };
    reply: {
      "generation": Schemas["org.sparewall.Firewall.Generation"];
    };
    role: "operator";
    streams: false;
  };
  /** Check a document without applying it: errors (as ValidationFailed, each naming its path) or warnings. */
  "org.sparewall.Firewall.Validate": {
    parameters: {
      "config": Record<string, unknown>;
    };
    reply: {
      "warnings": Array<string>;
    };
    role: "viewer";
    streams: false;
  };
  /** A WireGuard client configuration for remote-access peer `peer` (on `port`, one of the instance's ports, if given). */
  "org.sparewall.Firewall.VpnClientConfig": {
    parameters: {
      "instance"?: string | null;
      "peer": string;
      "port"?: number | null;
    };
    reply: {
      "config": string;
    };
    role: "admin";
    streams: false;
  };
  /** Delete a secret on this node. */
  "org.sparewall.Secrets.Delete": {
    parameters: {
      "name": string;
    };
    reply: Record<string, never>;
    role: "admin";
    streams: false;
  };
  /** Secrets' names, classes and versions, never their values. */
  "org.sparewall.Secrets.List": {
    parameters: Record<string, never>;
    reply: {
      "secrets": Array<Schemas["org.sparewall.Secrets.SecretInfo"]>;
    };
    role: "admin";
    streams: false;
  };
  /** Store a secret (a cluster secret unless `cluster` is false). Values can never be read back. */
  "org.sparewall.Secrets.Set": {
    parameters: {
      "cluster"?: boolean | null;
      "name": string;
      "value": string;
    };
    reply: {
      "secret": Schemas["org.sparewall.Secrets.SecretInfo"];
    };
    role: "admin";
    streams: false;
  };
  /** Whether a newer image is available on the channel (or `image`, a full reference). */
  "org.sparewall.Upgrade.Check": {
    parameters: {
      "channel"?: string | null;
      "image"?: string | null;
    };
    reply: {
      "available": boolean;
      "booted"?: string | null;
      "target": string;
    };
    role: "viewer";
    streams: false;
  };
  /** Start a rolling, health-gated upgrade; progress arrives as events (`Subscribe`). */
  "org.sparewall.Upgrade.Start": {
    parameters: {
      "channel"?: string | null;
      "image"?: string | null;
    };
    reply: {
      /** What happens next, in words. */
      "plan": Array<string>;
    };
    role: "admin";
    streams: false;
  };
}

export type Method = keyof Calls;
export type Parameters<M extends Method> = Calls[M]['parameters'];
export type Reply<M extends Method> = Calls[M]['reply'];
export type StreamingMethod = {[M in Method]: Calls[M]['streams'] extends true ? M : never}[Method];
