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
import { Conntrack, HealthState, SyncState } from '../../api/status.model';

const LEVEL_ICON: Record<string, string> = {
  ok: 'check_circle',
  degraded: 'warning',
  failed: 'error',
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
  protected readonly links = computed(() =>
    Object.entries((this.value()?.links ?? {}) as Record<string, string>),
  );

  protected readonly levelIcon = (level: string) => LEVEL_ICON[level] ?? 'help';

  private value() {
    return this.status.hasValue() ? this.status.value() : undefined;
  }
}
