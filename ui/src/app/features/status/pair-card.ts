import { Component, computed, inject, input, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { firstValueFrom } from 'rxjs';

import { ApiClient, CallFailed } from '../../api/api-client';
import { SyncState } from '../../api/status.model';
import { Session } from '../../core/session';
import { ConfirmData, ConfirmDialog } from '../../shared/confirm-dialog';

/**
 * Why this node can't hand the gateway to its peer now, as the node
 * itself would refuse (sparewalld failover.rs `decide`), or null.
 */
export function failoverBlocked(role: string | undefined, sync: SyncState): string | null {
  if (!sync.peer) return 'This node has no peer.';
  // A held pair (cluster.hold) claims no gateway addresses: both nodes'
  // VRRP is in FAULT, which the status reply shows as the role.
  if (role === 'FAULT') {
    return 'This node is in FAULT: the pair is held (cluster.hold), or the node is unwell, so no node claims the gateway addresses.';
  }
  if (role !== 'MASTER')
    return `Only the master hands the gateway over; this node is ${role ?? 'of unknown VRRP state'}.`;
  if (!sync.peer_reachable) return `${sync.peer} can't be reached.`;
  if (sync.state !== 'in-sync')
    return `The pair isn't in sync (${sync.state}): fail over only an in-sync pair.`;
  return null;
}

/**
 * A pair's two manual operations (#313), for operators and up: hand the
 * gateway to the peer (the pair never fails back by itself), and end a
 * divergence by keeping one node's configuration.
 */
@Component({
  selector: 'app-pair-card',
  imports: [MatButtonModule, MatCardModule, MatIconModule],
  template: `
    @if (sync(); as y) {
      @if (y.peer) {
        <mat-card appearance="outlined" data-testid="pair">
          <mat-card-header>
            <mat-icon matCardAvatar>sync_alt</mat-icon>
            <mat-card-title>Pair</mat-card-title>
            <mat-card-subtitle>{{ node() }} ({{ role() }}) and {{ y.peer }}</mat-card-subtitle>
          </mat-card-header>
          <mat-card-content>
            <p>
              {{ y.state === 'in-sync' ? 'In sync' : 'Sync: ' + y.state }}, at generation
              {{ y.active }}
              @if (y.peer_active !== null && y.peer_active !== y.active) {
                here and {{ y.peer_active }} on {{ y.peer }}
              }
              .
            </p>
            @if (result(); as r) {
              <p role="status">{{ r }}</p>
            }
            @if (failure(); as f) {
              <p class="problem" role="alert">{{ f }}</p>
            }
            @if (canAct() && blocked(); as why) {
              <p class="hint">{{ why }}</p>
            }
          </mat-card-content>
          @if (canAct()) {
            <mat-card-actions>
              <button matButton [disabled]="busy() || !!blocked()" (click)="failover(y)">
                <mat-icon>swap_horiz</mat-icon>
                Hand the gateway to {{ y.peer }}
              </button>
              @if (y.state === 'diverged') {
                <button matButton [disabled]="busy()" (click)="keep(y, node())">
                  Keep this node's (generation {{ y.active }})
                </button>
                <button matButton [disabled]="busy()" (click)="keep(y, y.peer)">
                  Take {{ y.peer }}'s (generation {{ y.peer_active }})
                </button>
              }
            </mat-card-actions>
          }
        </mat-card>
      }
    }
  `,
  styles: `
    .problem {
      color: var(--mat-sys-error);
    }
    .hint {
      color: var(--mat-sys-on-surface-variant);
      font: var(--mat-sys-body-small);
    }
  `,
})
export class PairCard {
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(MatDialog);
  private readonly session = inject(Session);
  readonly sync = input<SyncState | undefined>();
  readonly node = input.required<string>();
  readonly role = input<string | undefined>();
  protected readonly canAct = computed(() => this.session.can('operator'));
  protected readonly blocked = computed(() => {
    const y = this.sync();
    return y ? failoverBlocked(this.role(), y) : 'No pair.';
  });
  protected readonly busy = signal(false);
  protected readonly result = signal<string | null>(null);
  protected readonly failure = signal<string | null>(null);

  protected async failover(y: SyncState): Promise<void> {
    if (
      !(await this.confirm(
        `Hand the gateway to ${y.peer}?`,
        `${y.peer} takes the gateway addresses, and ${this.node()} becomes the backup. The pair never fails back by itself: hand it back the same way.`,
        'Fail over',
      ))
    ) {
      return;
    }
    await this.run(async () => {
      const r = await this.api.call('org.sparewall.Cluster.Failover', { to: y.peer });
      return r.message;
    });
  }

  protected async keep(y: SyncState, from: string | null): Promise<void> {
    if (!from) return;
    const here = from === this.node();
    if (
      !(await this.confirm(
        here ? `Keep ${this.node()}'s configuration?` : `Take ${from}'s configuration?`,
        here
          ? `${y.peer} runs generation ${y.active}'s configuration, from ${this.node()}, in place of its own (generation ${y.peer_active}).`
          : `${this.node()} runs ${from}'s configuration (generation ${y.peer_active}) in place of its own (generation ${y.active}).`,
        'Sync',
      ))
    ) {
      return;
    }
    await this.run(async () => {
      const r = await this.api.call('org.sparewall.Firewall.Sync', { from_node: from });
      return `Both nodes run ${from}'s configuration: generation ${r.generation.id} here.`;
    });
  }

  private async run(act: () => Promise<string>): Promise<void> {
    this.busy.set(true);
    this.result.set(null);
    this.failure.set(null);
    try {
      this.result.set(await act());
    } catch (e) {
      this.failure.set(e instanceof CallFailed ? e.message : 'It failed.');
    } finally {
      this.busy.set(false);
    }
  }

  private async confirm(title: string, text: string, action: string): Promise<boolean> {
    return !!(await firstValueFrom(
      this.dialog
        .open<ConfirmDialog, ConfirmData, boolean>(ConfirmDialog, { data: { title, text, action } })
        .afterClosed(),
    ));
  }
}
