import { Service, inject, signal } from '@angular/core';

import { ApiClient, CallFailed } from '../api/api-client';
import { Session } from './session';

/** An event from `Subscribe`: an apply, a rollback, a health or peer change. */
export type NodeEvent = Record<string, unknown> & { type?: string };

const RETRY_MS = [1000, 2000, 5000, 10000];

/**
 * The node's events, from one `Subscribe` stream shared by every page.
 * `count` changes with each one, so a page can reload what it shows.
 */
@Service()
export class NodeEvents {
  private readonly api = inject(ApiClient);
  private readonly session = inject(Session);
  private abort?: AbortController;

  private readonly lastEvent = signal<NodeEvent | undefined>(undefined);
  private readonly seen = signal(0);
  private readonly up = signal(false);

  readonly last = this.lastEvent.asReadonly();
  readonly count = this.seen.asReadonly();
  /** Whether the stream is open: false while the node cannot be reached. */
  readonly connected = this.up.asReadonly();

  start(): void {
    if (this.abort) return;
    const abort = new AbortController();
    this.abort = abort;
    void this.run(abort.signal);
  }

  stop(): void {
    this.abort?.abort();
    this.abort = undefined;
    this.up.set(false);
  }

  private async run(signal: AbortSignal): Promise<void> {
    let failures = 0;
    while (!signal.aborted) {
      try {
        for await (const r of this.api.stream('org.sparewall.Firewall.Subscribe', {}, signal)) {
          failures = 0;
          this.up.set(true);
          this.lastEvent.set(r.event as NodeEvent);
          this.seen.update((n) => n + 1);
        }
      } catch (e) {
        // Refused: over HTTP (401) when the session has ended, or as the
        // stream's first record when there is none at all.
        if (
          e instanceof CallFailed &&
          (e.status === 401 || e.error === 'org.sparewall.Firewall.PermissionDenied')
        ) {
          this.stop();
          this.session.ended();
          return;
        }
      }
      this.up.set(false);
      if (signal.aborted) return;
      await new Promise((r) => setTimeout(r, RETRY_MS[Math.min(failures++, RETRY_MS.length - 1)]));
    }
  }
}
