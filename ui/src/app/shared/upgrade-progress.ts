/**
 * An upgrade started from the web UI (#191), followed through its events
 * (`{"type": "upgrade", "step", "detail"}`) and across the reboot of the
 * node that serves the UI.
 */
export type Phase = 'running' | 'rebooting' | 'done' | 'failed';

export interface Progress {
  phase: Phase;
  /** What the node said it will do (Upgrade.Start's reply). */
  plan: string[];
  /** Each step's message, as it arrives. */
  log: string[];
  /** Whether a step reboots the node the UI is served by. */
  rebootsHere: boolean;
  /** The failure, or the outcome once done. */
  message?: string;
}

export type Input =
  | { kind: 'event'; event: Record<string, unknown> }
  /** The event stream dropped. */
  | { kind: 'disconnected' }
  /** The node answers again after its reboot, with what its status says. */
  | { kind: 'back'; outcome: string };

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
      const rebootsHere =
        p.rebootsHere ||
        step === 'reboot' ||
        (step === 'stage-peer' && detail.endsWith(` on ${node}`));
      if (step === 'failed') return { ...p, log, rebootsHere, phase: 'failed', message: detail };
      if (step === 'done') return { ...p, log, rebootsHere, phase: 'done', message: detail };
      return { ...p, log, rebootsHere };
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
      return p.phase === 'rebooting' ? { ...p, phase: 'done', message: input.outcome } : p;
  }
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
