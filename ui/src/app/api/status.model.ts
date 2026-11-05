// The parts of Firewall.Status whose shape the Varlink interface leaves
// open (`object`), as the coordinator fills them (sparewalld service.rs).

export interface SyncState {
  active: number;
  confirmed: number;
  pending: { id: number; reverts_in: number } | null;
  desired_hash: string;
  applied_hash: string | null;
  /** `standalone`, or the pair's sync state. */
  state: string;
  peer: string | null;
  peer_reachable: boolean | null;
  peer_active: number | null;
  /** This node's booted image and its peer's (`name@digest`). */
  image?: string | null;
  peer_image?: string | null;
  last_error: string | null;
}

/** The background update check (#188): the status reply's `update`. */
export interface UpdateState {
  enabled: boolean;
  running: string;
  target?: string;
  /** Absent until a check succeeds. */
  available?: 'none' | 'newer' | 'rebuild' | 'different';
  version?: string;
  digest?: string;
  checked?: string;
  succeeded?: string;
  error?: string;
}

export interface HealthState {
  level: 'ok' | 'degraded' | 'failed';
  checks: { name: string; level: string; message: string }[];
}

export interface Conntrack {
  count: number | null;
  max: number | null;
}

/** An address or prefix, with the seconds left of its lifetimes (absent: forever). */
export interface Lifetimed {
  address: string;
  preferred_seconds?: number;
  valid_seconds?: number;
}

/** One network's IPv6 state (#216): an entry of the status reply's `ipv6`. */
export interface Ipv6Network {
  iface: string;
  mode: 'dhcpv6' | 'ra' | 'static' | 'delegated';
  addresses?: Lifetimed[];
  /** Prefixes DHCPv6 delegated to the link (a WAN). */
  delegated?: Lifetimed[];
  default_gateway?: string;
  /** An inside network's: the prefixes it advertises. */
  prefixes?: string[];
}
