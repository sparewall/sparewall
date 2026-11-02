/**
 * An upgrade started from the web UI (#191), followed through its events
 * (`{"type": "upgrade", "step", "detail"}`) and across the reboot of the
 * node that serves the UI.
 */
export type Phase = 'running' | 'rebooting' | 'finishing' | 'done' | 'failed';

export interface Progress {
  phase: Phase;
  /** What the node said it will do (Upgrade.Start's reply). */
  plan: string[];
  /** Each step's message, as it arrives. */
  log: string[];
  /** Whether a step reboots the node the UI is served by. */
  rebootsHere: boolean;
  /**
   * The master that staged this node, when it is the pair's standby: it
   * goes on alone once this node is back (its relay ends with the reboot).
   */
  master?: string;
  /** The failure, or the outcome once done. */
  message?: string;
}

export type Input =
  | { kind: 'event'; event: Record<string, unknown> }
  /** The event stream dropped. */
  | { kind: 'disconnected' }
  /** The node answers again after its reboot, with what its status says. */
  | { kind: 'back'; outcome: string }
  /** While the master finishes: whether both nodes now run the same image, in sync. */
  | { kind: 'pair'; finished: boolean; outcome: string }
  /** The master did not finish in time. */
  | { kind: 'timeout' };

export function started(plan: string[]): Progress {
  return { phase: 'running', plan, log: [], rebootsHere: false };
}

/** The next state; `node` is the name of the node the UI is served by. */
export function advance(p: Progress, input: Input, node: string): Progress {
  switch (input.kind) {
    case 'event': {
      const e = input.event;
      if (e['type'] !== 'upgrade' || (p.phase !== 'running' && p.phase !== 'rebooting')) return p;
      const step = String(e['step'] ?? '');
      const detail = String(e['detail'] ?? '');
      if (step === 'plan') return p;
      const log = detail ? [...p.log, detail] : p.log;
      // This node's own reboot (a standalone node, or the master at the
      // end), or, relayed from the master, the staging of this node.
      const staged = step === 'stage-peer' && detail.endsWith(` on ${node}`);
      const rebootsHere = p.rebootsHere || step === 'reboot' || staged;
      // A relayed event reads "<master>: …".
      const master = staged ? detail.split(':')[0] : p.master;
      const next = { ...p, log, rebootsHere, master };
      if (step === 'failed') return { ...next, phase: 'failed', message: detail };
      if (step === 'done') return { ...next, phase: 'done', message: detail };
      return next;
    }
    case 'disconnected':
      if (p.phase !== 'running') return p;
      return p.rebootsHere
        ? { ...p, phase: 'rebooting', message: `${node} is rebooting into the new image.` }
        : {
            ...p,
            phase: 'failed',
            message: `The connection to ${node} was lost during the upgrade.`,
          };
    case 'back':
      if (p.phase !== 'rebooting') return p;
      // A standby back on the new image: the master still hands over and
      // upgrades itself, which this page follows from status.
      return p.master
        ? {
            ...p,
            phase: 'finishing',
            message: `${input.outcome} ${p.master} now hands over and upgrades itself.`,
          }
        : { ...p, phase: 'done', message: input.outcome };
    case 'pair':
      return p.phase === 'finishing' && input.finished
        ? { ...p, phase: 'done', message: input.outcome }
        : p;
    case 'timeout':
      return p.phase === 'finishing'
        ? {
            ...p,
            phase: 'failed',
            message: `${p.master} has not finished its part: see its status, or run sparewall upgrade again.`,
          }
        : p;
  }
}

/** Whether a pair has finished: both nodes on the same image, in sync. */
export function pairFinished(sync: {
  image?: string | null;
  peer_image?: string | null;
  peer_reachable?: boolean | null;
  state?: string;
}): boolean {
  const digest = (i: string | null | undefined) => i?.split('@').pop();
  return (
    sync.peer_reachable === true &&
    sync.state === 'in-sync' &&
    !!digest(sync.image) &&
    digest(sync.image) === digest(sync.peer_image)
  );
}

/** What a node says once it is back: its version, health and, in a pair, sync. */
export function outcome(
  node: string,
  status: {
    update?: { running?: string } | null;
    health?: { level?: string };
    sync?: { peer?: string | null; state?: string };
  },
): string {
  const version = status.update?.running ?? 'its new image';
  const health = status.health?.level ?? 'unknown';
  const pair = status.sync?.peer ? `, ${status.sync.state} with ${status.sync.peer}` : '';
  return `${node} is back, running ${version}: health ${health}${pair}.`;
}
