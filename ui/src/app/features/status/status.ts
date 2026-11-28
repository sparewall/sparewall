import { DecimalPipe, PercentPipe } from '@angular/common';
import { httpResource } from '@angular/common/http';
import { Component, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSnackBar } from '@angular/material/snack-bar';
import { firstValueFrom } from 'rxjs';

import { ApiClient, CallFailed, callUrl } from '../../api/api-client';
import { Reply } from '../../api/api.model';
import { NodeEvents } from '../../core/node-events';
import { Session } from '../../core/session';
import { ConfirmData, ConfirmDialog } from '../../shared/confirm-dialog';
import {
  Conntrack,
  HealthState,
  Ipv6Network,
  Lifetimed,
  SyncState,
  UpdateState,
} from '../../api/status.model';
import { checkProblem, mixedImages, updateNotice } from '../../shared/update-notice';
import { MetricsHistory } from './history';
import { UpgradePanel } from './upgrade-panel';

const LEVEL_ICON: Record<string, string> = {
  ok: 'check_circle',
  degraded: 'warning',
  failed: 'error',
};

const LEVEL_TEXT: Record<string, string> = {
  ok: 'Healthy',
  degraded: 'Degraded',
  failed: 'Failed',
};

/**
 * Checks that stay degraded until someone has seen them, and clear with
 * `sparewall health ack` (#314): SELinux denials for the coordinator, and
 * a scheduled upgrade that failed.
 */
export const ACKABLE = ['selinux', 'upgrade'];

/** The node at a glance, kept current by its events. */
@Component({
  selector: 'app-status',
  imports: [
    DecimalPipe,
    PercentPipe,
    MatButtonModule,
    MatCardModule,
    MatChipsModule,
    MatIconModule,
    MatProgressBarModule,
    UpgradePanel,
    MetricsHistory,
  ],
  templateUrl: './status.html',
  styleUrl: './status.scss',
})
export class Status {
  private readonly events = inject(NodeEvents);
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(MatDialog);
  private readonly snack = inject(MatSnackBar);
  protected readonly session = inject(Session);
  protected readonly acking = signal(false);

  /** Whether an admin can acknowledge this check here. */
  protected ackable(c: { name: string; level: string }): boolean {
    return c.level !== 'ok' && ACKABLE.includes(c.name) && this.session.can('admin');
  }

  /** Acknowledge a check on this node, after showing what is acknowledged. */
  protected async ack(c: { name: string; message: string }): Promise<void> {
    const ok = await firstValueFrom(
      this.dialog
        .open<ConfirmDialog, ConfirmData, boolean>(ConfirmDialog, {
          data: {
            title: `Acknowledge ${c.name}?`,
            text: `${c.message.replace(/;? acknowledge with: sparewall health ack \S+/, '')}. The check is ok again until there's something new; it records who acknowledged it.`,
            action: 'Acknowledge',
          },
        })
        .afterClosed(),
    );
    if (!ok) return;
    this.acking.set(true);
    try {
      await this.api.call('org.sparewall.Firewall.AckHealth', { name: c.name });
      this.snack.open(`Acknowledged ${c.name}.`, undefined, { duration: 4000 });
      this.status.reload();
    } catch (e) {
      this.snack.open(e instanceof CallFailed ? e.message : 'Acknowledging failed.', 'Close');
    } finally {
      this.acking.set(false);
    }
  }

  protected readonly status = httpResource<Reply<'org.sparewall.Firewall.Status'>>(() => {
    // Read again on every event: an apply, a rollback, a health change.
    this.events.count();
    return { url: callUrl('org.sparewall.Firewall.Status'), method: 'POST', body: {} };
  });

  protected readonly sync = computed(() => this.value()?.sync as SyncState | undefined);
  protected readonly health = computed(() => this.value()?.health as HealthState | undefined);
  protected readonly conntrack = computed(() => this.value()?.conntrack as Conntrack | undefined);
  protected readonly update = computed(() => this.value()?.update as UpdateState | undefined);
  protected readonly notice = computed(() => updateNotice(this.update()));
  protected readonly checkProblem = computed(() => checkProblem(this.update()));
  protected readonly mixed = computed(() => mixedImages(this.sync()));
  protected readonly upgradeDocs =
    'https://github.com/sparewall/sparewall/blob/main/docs/operations.md#upgrades';
  protected readonly links = computed(() =>
    Object.entries((this.value()?.links ?? {}) as Record<string, string>),
  );

  protected readonly ipv6 = computed(() =>
    Object.entries((this.value()?.ipv6 ?? {}) as Record<string, Ipv6Network>),
  );

  protected readonly levelIcon = (level: string) => LEVEL_ICON[level] ?? 'help';

  protected levelText(level: string): string {
    return LEVEL_TEXT[level] ?? level;
  }

  /** Seconds as `1h30m`, `45m` or `30s`. */
  protected duration(s: number): string {
    if (s < 60) return `${s}s`;
    if (s < 3600) return `${Math.floor(s / 60)}m`;
    const m = Math.floor((s % 3600) / 60);
    return m ? `${Math.floor(s / 3600)}h${m}m` : `${Math.floor(s / 3600)}h`;
  }

  /** A delegated prefix's lifetimes left: `preferred 30m, valid 1h`. */
  protected lifetimes(d: Lifetimed): string {
    const parts: string[] = [];
    if (d.preferred_seconds !== undefined)
      parts.push(`preferred ${this.duration(d.preferred_seconds)}`);
    if (d.valid_seconds !== undefined) parts.push(`valid ${this.duration(d.valid_seconds)}`);
    return parts.join(', ');
  }

  /** What is wrong, by check, or that nothing is. */
  protected summary(h: HealthState): string {
    const bad = h.checks.filter((c) => c.level !== 'ok').map((c) => c.name);
    return bad.length
      ? `Needs attention: ${bad.join(', ')}.`
      : `All ${h.checks.length} checks pass.`;
  }

  private value() {
    return this.status.hasValue() ? this.status.value() : undefined;
  }
}
