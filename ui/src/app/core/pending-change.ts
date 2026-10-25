import { Service, computed, inject, linkedSignal, signal } from '@angular/core';

import { ApiClient } from '../api/api-client';
import { SyncState } from '../api/status.model';
import { NodeStatus } from './node-status';

/**
 * A generation that waits for confirmation, and the seconds left before
 * the node reverts it by itself, counted down here between the node's
 * events.
 */
@Service()
export class PendingChange {
  private readonly api = inject(ApiClient);
  private readonly status = inject(NodeStatus).status;
  private readonly now = signal(Date.now());

  /** The pending generation and when it reverts (ms since the epoch). */
  private readonly pending = linkedSignal(() => {
    const p = this.status.hasValue()
      ? (this.status.value().sync as unknown as SyncState).pending
      : null;
    return p ? { id: p.id, deadline: Date.now() + p.reverts_in * 1000 } : undefined;
  });

  readonly id = computed(() => this.pending()?.id);
  readonly secondsLeft = computed(() => {
    const p = this.pending();
    return p ? Math.max(0, Math.ceil((p.deadline - this.now()) / 1000)) : 0;
  });

  constructor() {
    setInterval(() => this.now.set(Date.now()), 1000);
  }

  async confirm(): Promise<void> {
    const id = this.id();
    if (id === undefined) return;
    await this.api.call('org.sparewall.Firewall.Confirm', { id });
    this.pending.set(undefined);
    this.status.reload();
  }

  /** Go back to the generation before the pending one now, without waiting. */
  async revert(): Promise<void> {
    await this.api.call('org.sparewall.Firewall.Rollback', {});
    this.pending.set(undefined);
    this.status.reload();
  }
}
