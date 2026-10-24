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
  last_error: string | null;
}

export interface HealthState {
  level: 'ok' | 'degraded' | 'failed';
  checks: { name: string; level: string; message: string }[];
}

export interface Conntrack {
  count: number | null;
  max: number | null;
}
