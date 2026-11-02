import { Component, DestroyRef, effect, inject, input, signal, untracked } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { firstValueFrom } from 'rxjs';

import { ApiClient, CallFailed } from '../../api/api-client';
import { NodeEvents } from '../../core/node-events';
import { Session } from '../../core/session';
import { ConfirmDialog, ConfirmData } from '../../shared/confirm-dialog';
import { Progress, advance, outcome, pairFinished, started } from '../../shared/upgrade-progress';

const STOPPED_HALFWAY =
  'https://github.com/sparewall/sparewall/blob/main/docs/operations.md#upgrades';

/**
 * Start an upgrade from the web UI (#191), for admins: confirm, follow
 * its steps, and wait out the reboot of the node that serves the UI.
 */
@Component({
  selector: 'app-upgrade-panel',
  imports: [MatButtonModule, MatProgressBarModule],
  template: `
    @if (!session.can('admin')) {
      <p>An admin can upgrade from here.</p>
    } @else {
      @switch (progress()?.phase) {
        @case (undefined) {
          <button matButton="filled" (click)="confirm()" [disabled]="busy()">Upgrade…</button>
          @if (problem(); as e) {
            <p class="problem" role="alert">{{ e }}</p>
          }
        }
        @case ('running') {
          <p role="status">Upgrading…</p>
          <mat-progress-bar mode="indeterminate" />
        }
        @case ('rebooting') {
          <p role="status">{{ progress()?.message }} This page reconnects when it is back.</p>
          <mat-progress-bar mode="indeterminate" />
        }
        @case ('finishing') {
          <p role="status">{{ progress()?.message }}</p>
          <mat-progress-bar mode="indeterminate" />
        }
        @case ('done') {
          <p role="status">{{ progress()?.message }}</p>
        }
        @case ('failed') {
          <p class="problem" role="alert">The upgrade stopped: {{ progress()?.message }}</p>
          @if (paired()) {
            <p>
              <a [href]="docs" target="_blank" rel="noopener">If a run stops halfway</a>: running it
              again finishes it.
            </p>
          }
        }
      }
      @if (progress(); as p) {
        @if (p.log.length) {
          <ol class="steps">
            @for (l of p.log; track $index) {
              <li>{{ l }}</li>
            }
          </ol>
        }
      }
    }
  `,
  styles: `
    .steps {
      margin: 8px 0 0;
      padding-left: 20px;
      font: var(--mat-sys-body-small);
    }
  `,
})
export class UpgradePanel {
  /** The node serving the UI, and whether it is one of a pair. */
  readonly node = input.required<string>();
  readonly paired = input(false);
  /** What the notice offers, for the confirmation. */
  readonly offer = input<string>('');

  protected readonly session = inject(Session);
  private readonly api = inject(ApiClient);
  private readonly events = inject(NodeEvents);
  private readonly dialog = inject(MatDialog);
  protected readonly docs = STOPPED_HALFWAY;

  protected readonly progress = signal<Progress | undefined>(undefined);
  protected readonly busy = signal(false);
  protected readonly problem = signal<string | undefined>(undefined);

  /** How often the node is asked again, and how long the master may take. */
  static readonly RETRY_MS = 5000;
  static readonly POLL_MS = 10000;
  static readonly FINISH_MS = 30 * 60 * 1000;
  private timer?: ReturnType<typeof setInterval>;
  private finishBy = 0;

  constructor() {
    inject(DestroyRef).onDestroy(() => this.stopTimer());
    // Each upgrade event, in order.
    this.events.events$.pipe(takeUntilDestroyed(inject(DestroyRef))).subscribe((event) => {
      // Another run's events (the other node's, or a CLI's) block a second start.
      if (event['type'] === 'upgrade' && !this.progress()) {
        this.busy.set(!['done', 'failed', 'reboot'].includes(String(event['step'])));
      }
      this.step({ kind: 'event', event });
    });
    // The stream drops when the node reboots, and comes back with it.
    effect(() => {
      const up = this.events.connected();
      untracked(() => {
        if (!up) {
          this.step({ kind: 'disconnected' });
        } else if (this.progress()?.phase === 'rebooting') {
          // Until status answers: the stream may be back before the rest.
          void this.back();
          this.startTimer(UpgradePanel.RETRY_MS, () => void this.back());
        }
      });
    });
  }

  protected async confirm(): Promise<void> {
    this.problem.set(undefined);
    const steps = this.paired()
      ? 'The master downloads the new image, the standby is upgraded and rebooted, the ' +
        'master hands it the gateway addresses, then reboots.'
      : `${this.node()} stages the new image and reboots: one reboot of downtime.`;
    const data: ConfirmData = {
      title: 'Upgrade?',
      text: `${this.offer() || 'Upgrade to the newest image on the channel.'} ${steps}`,
      action: 'Upgrade',
    };
    const yes = await firstValueFrom(this.dialog.open(ConfirmDialog, { data }).afterClosed());
    if (yes !== true) return;
    this.busy.set(true);
    try {
      const r = await this.api.call('org.sparewall.Upgrade.Start', {});
      this.progress.set(started(r.plan));
    } catch (e) {
      this.problem.set(e instanceof CallFailed ? e.message : String(e));
      this.busy.set(false);
    }
  }

  private step(input: Parameters<typeof advance>[1]): void {
    const p = this.progress();
    if (p) this.progress.set(advance(p, input, this.node()));
  }

  private async back(): Promise<void> {
    if (this.progress()?.phase !== 'rebooting') return;
    try {
      const s = await this.api.call('org.sparewall.Firewall.Status', {});
      this.step({ kind: 'back', outcome: outcome(s.node, s as never) });
    } catch {
      // Not answering yet: the timer asks again.
      return;
    }
    this.stopTimer();
    if (this.progress()?.phase === 'finishing') {
      // The master goes on alone: follow it from this node's status.
      this.finishBy = Date.now() + UpgradePanel.FINISH_MS;
      this.startTimer(UpgradePanel.POLL_MS, () => void this.finishing());
    }
  }

  private async finishing(): Promise<void> {
    if (this.progress()?.phase !== 'finishing') {
      this.stopTimer();
      return;
    }
    if (Date.now() > this.finishBy) {
      this.step({ kind: 'timeout' });
      this.stopTimer();
      return;
    }
    try {
      const s = await this.api.call('org.sparewall.Firewall.Status', {});
      const sync = s.sync as Parameters<typeof pairFinished>[0];
      const version =
        (s.update as { running?: string } | null | undefined)?.running ?? 'the new image';
      this.step({
        kind: 'pair',
        finished: pairFinished(sync),
        outcome: `Both nodes run ${version}, in sync.`,
      });
    } catch {
      // Asked again at the next tick.
    }
    if (this.progress()?.phase !== 'finishing') this.stopTimer();
  }

  private startTimer(ms: number, f: () => void): void {
    this.stopTimer();
    this.timer = setInterval(f, ms);
  }

  private stopTimer(): void {
    if (this.timer !== undefined) clearInterval(this.timer);
    this.timer = undefined;
  }
}
