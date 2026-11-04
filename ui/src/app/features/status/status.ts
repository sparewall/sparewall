import { DecimalPipe, PercentPipe } from '@angular/common';
import { httpResource } from '@angular/common/http';
import { Component, computed, inject } from '@angular/core';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatIconModule } from '@angular/material/icon';
import { MatProgressBarModule } from '@angular/material/progress-bar';

import { callUrl } from '../../api/api-client';
import { Reply } from '../../api/api.model';
import { NodeEvents } from '../../core/node-events';
import { Session } from '../../core/session';
import {
  Conntrack,
  HealthState,
  Ipv6Network,
  Lifetimed,
  SyncState,
  UpdateState,
} from '../../api/status.model';
import { checkProblem, mixedImages, updateNotice } from '../../shared/update-notice';
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

/** The node at a glance, kept current by its events. */
@Component({
  selector: 'app-status',
  imports: [
    DecimalPipe,
    PercentPipe,
    MatCardModule,
    MatChipsModule,
    MatIconModule,
    MatProgressBarModule,
    UpgradePanel,
  ],
  templateUrl: './status.html',
  styleUrl: './status.scss',
})
export class Status {
  private readonly events = inject(NodeEvents);
  protected readonly session = inject(Session);

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
