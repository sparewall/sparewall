import { SyncState, UpdateState } from '../api/status.model';

const RELEASES = 'https://github.com/sparewall/sparewall/releases/tag/v';

/** What the update check offers, as the status page shows it. */
export interface UpdateNotice {
  kind: 'newer' | 'rebuild' | 'different';
  /** One line: "0.4.1 is available". */
  title: string;
  running: string;
  /** The release notes of what is offered, when it is a release. */
  notes?: string;
}

/** The notice for an update on offer, or nothing (none, not checked yet, off, an older node). */
export function updateNotice(u: UpdateState | null | undefined): UpdateNotice | undefined {
  if (!u?.enabled) return undefined;
  const running = u.running;
  switch (u.available) {
    case 'newer': {
      const v = u.version ?? 'A newer version';
      return { kind: 'newer', title: `${v} is available`, running, notes: releaseNotes(u.version) };
    }
    case 'rebuild':
      // The same release, rebuilt (base image updates): its notes are the running version's.
      return {
        kind: 'rebuild',
        title: `A rebuild of ${running} is available`,
        running,
        notes: releaseNotes(running),
      };
    case 'different':
      return {
        kind: 'different',
        title: `A different image is available on ${u.target ?? 'the channel'}`,
        running,
      };
    default:
      return undefined;
  }
}

/** Why the last check failed, while it does: informational, never a health problem. */
export function checkProblem(u: UpdateState | null | undefined): string | undefined {
  if (!u?.enabled || !u.error) return undefined;
  const since = u.succeeded ? ` The last successful check was at ${u.succeeded}.` : '';
  return `The last update check failed: ${u.error}.${since}`;
}

/** A pair whose nodes run different images: usually an upgrade that stopped halfway. */
export function mixedImages(y: SyncState | null | undefined): string | undefined {
  if (!y?.peer || y.peer_reachable !== true) return undefined;
  const digest = (i: string | null | undefined) => i?.split('@').pop();
  const ours = digest(y.image);
  const theirs = digest(y.peer_image);
  if (!ours || !theirs || ours === theirs) return undefined;
  return `This node and ${y.peer} run different images. If an upgrade stopped halfway, running it again finishes it.`;
}

function releaseNotes(version: string | undefined): string | undefined {
  // Releases only: a build between releases (0.4.1-dev.3+g…) has no notes.
  return version && /^\d+\.\d+\.\d+(-rc\d+)?$/.test(version) ? RELEASES + version : undefined;
}
