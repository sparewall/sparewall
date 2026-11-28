import { httpResource } from '@angular/common/http';
import { Component, computed, inject, input, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';
import { RouterLink } from '@angular/router';

import { ApiClient, CallFailed, callUrl } from '../../api/api-client';
import { Reply } from '../../api/api.model';
import { Session } from '../../core/session';

/** The unit the backup timer runs, for the Logs page's filter. */
export const BACKUP_UNIT = 'sparewall-backup.service';

/**
 * Backups (#311): the schedule and repository, the last run (the `backup`
 * health check's word), and, for admins, a backup now. Restoring stays on
 * the console: it rebuilds a node's state directory.
 */
@Component({
  selector: 'app-backup-card',
  imports: [MatButtonModule, MatCardModule, MatIconModule, RouterLink],
  template: `
    <mat-card appearance="outlined" data-testid="backup">
      <mat-card-header>
        <mat-icon matCardAvatar>backup</mat-icon>
        <mat-card-title>Backups</mat-card-title>
        <mat-card-subtitle>{{ schedule() }}</mat-card-subtitle>
      </mat-card-header>
      <mat-card-content>
        @if (repository(); as r) {
          <p>
            Sent to <code>{{ r }}</code>.
          </p>
        } @else if (enabled()) {
          <p>Kept on the node only: no repository is set.</p>
        }
        @if (check(); as c) {
          <p [class.problem]="c.level !== 'ok'">
            {{ c.level === 'ok' ? 'The ' + c.message + '.' : c.message }}
          </p>
          @if (c.level !== 'ok') {
            <p><a [routerLink]="['/logs']" [queryParams]="{ unit: unit }">The backup's logs</a></p>
          }
        }
        @if (result(); as r) {
          <dl class="result" role="status">
            <dt>Bundle</dt>
            <dd>
              <code>{{ r.path }}</code>
            </dd>
            <dt>Digest</dt>
            <dd>
              <code>{{ r.digest }}</code>
            </dd>
            @if (r.snapshot) {
              <dt>Snapshot</dt>
              <dd>
                <code>{{ r.snapshot }}</code>
              </dd>
            }
            <dt>Secrets sealed</dt>
            <dd>
              {{ r.secrets.length ? r.secrets.join(', ') : 'none: no backup password is set' }}
            </dd>
          </dl>
        }
        @if (failure(); as f) {
          <p class="problem" role="alert">
            {{ f }} <a [routerLink]="['/logs']" [queryParams]="{ unit: unit }">Logs</a>
          </p>
        }
        <p class="hint">
          Restoring a bundle is done on the node's console: <code>sparewall restore</code>.
        </p>
      </mat-card-content>
      @if (session.can('admin')) {
        <mat-card-actions>
          <button matButton [disabled]="busy()" (click)="backup()">
            <mat-icon>backup</mat-icon>
            Back up now
          </button>
        </mat-card-actions>
      }
    </mat-card>
  `,
  styles: `
    .problem {
      color: var(--mat-sys-error);
    }
    .hint {
      color: var(--mat-sys-on-surface-variant);
      font: var(--mat-sys-body-small);
    }
    .result {
      display: grid;
      grid-template-columns: auto 1fr;
      gap: 2px 12px;
      dd {
        margin: 0;
        overflow-wrap: anywhere;
      }
    }
  `,
})
export class BackupCard {
  private readonly api = inject(ApiClient);
  protected readonly session = inject(Session);
  /** The `backup` health check, if the node has one. */
  readonly check = input<{ name: string; level: string; message: string } | undefined>();
  protected readonly unit = BACKUP_UNIT;

  private readonly config = httpResource<Reply<'org.sparewall.Firewall.GetConfig'>>(() => ({
    url: callUrl('org.sparewall.Firewall.GetConfig'),
    method: 'POST',
    body: {},
  }));
  private readonly settings = computed(() =>
    this.config.hasValue() ? (this.config.value().config.backup ?? null) : null,
  );
  protected readonly enabled = computed(() => this.settings()?.enabled ?? false);
  protected readonly repository = computed(() => this.settings()?.repository ?? null);
  protected readonly schedule = computed(() => {
    const b = this.settings();
    if (!b?.enabled) return 'No scheduled backups';
    return b.schedule ? `Scheduled: ${b.schedule}` : 'Scheduled hourly';
  });
  protected readonly busy = signal(false);
  protected readonly result = signal<Reply<'org.sparewall.Firewall.Backup'> | null>(null);
  protected readonly failure = signal<string | null>(null);

  protected async backup(): Promise<void> {
    this.busy.set(true);
    this.failure.set(null);
    this.result.set(null);
    try {
      this.result.set(await this.api.call('org.sparewall.Firewall.Backup', {}));
    } catch (e) {
      this.failure.set(e instanceof CallFailed ? e.message : 'The backup failed.');
    } finally {
      this.busy.set(false);
    }
  }
}
