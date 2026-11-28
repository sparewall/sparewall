import { DatePipe } from '@angular/common';
import { httpResource } from '@angular/common/http';
import { Component, computed, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { firstValueFrom } from 'rxjs';

import { ApiClient, CallFailed, callUrl } from '../../api/api-client';
import { Reply, Schemas } from '../../api/api.model';
import { NodeStatus } from '../../core/node-status';
import { ConfirmData, ConfirmDialog } from '../../shared/confirm-dialog';
import { PasswordCheck } from './password-check';
import { references } from './references';
import { SecretData, SecretDialog, SecretResult } from './secret-dialog';

type Secret = Schemas['org.sparewall.Secrets.SecretInfo'];

/** The backup password's secret (#142). */
export const BACKUP_PASSWORD = 'backup-password';

/**
 * Secrets (#309, admin only): their names, classes and versions, never
 * their values, which can't be read back. Add, replace and delete them,
 * and check the backup password.
 */
@Component({
  selector: 'app-secrets',
  imports: [DatePipe, MatButtonModule, MatIconModule, MatTableModule],
  templateUrl: './secrets.html',
  styles: `
    table {
      width: 100%;
    }
    .problem {
      color: var(--mat-sys-error);
    }
    .actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
  `,
})
export class Secrets {
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(MatDialog);
  private readonly snack = inject(MatSnackBar);
  private readonly node = inject(NodeStatus);

  protected readonly secrets = httpResource<Reply<'org.sparewall.Secrets.List'>>(() => ({
    url: callUrl('org.sparewall.Secrets.List'),
    method: 'POST',
    body: {},
  }));
  /** The running document, for the settings that reference a secret. */
  private readonly config = httpResource<Reply<'org.sparewall.Firewall.GetConfig'>>(() => ({
    url: callUrl('org.sparewall.Firewall.GetConfig'),
    method: 'POST',
    body: {},
  }));
  protected readonly columns = ['name', 'class', 'version', 'updated', 'used', 'actions'];
  protected readonly busy = signal(false);
  protected readonly pair = computed(() => this.node.peer() !== null);
  protected readonly hasBackupPassword = computed(
    () =>
      this.secrets.hasValue() &&
      this.secrets.value().secrets.some((s) => s.name === BACKUP_PASSWORD),
  );

  protected usedBy(s: Secret): string[] {
    return this.config.hasValue() ? references(this.config.value().config, s.name) : [];
  }

  protected async set(name?: string): Promise<void> {
    const r = await firstValueFrom(
      this.dialog
        .open<SecretDialog, SecretData, SecretResult>(SecretDialog, {
          data: { name, pair: this.pair() },
          width: '480px',
        })
        .afterClosed(),
    );
    if (!r) return;
    const taken =
      this.secrets.hasValue() && this.secrets.value().secrets.some((s) => s.name === r.name);
    if (!name && taken) {
      const ok = await this.confirm(
        `Replace ${r.name}?`,
        `A secret named ${r.name} exists: its value is replaced, and its version goes up.`,
        'Replace',
      );
      if (!ok) return;
    }
    this.busy.set(true);
    try {
      const done = await this.api.call('org.sparewall.Secrets.Set', {
        name: r.name,
        value: r.value,
        cluster: r.cluster,
      });
      this.snack.open(`Set ${r.name}, version ${done.secret.version}.`, undefined, {
        duration: 4000,
      });
      this.secrets.reload();
    } catch (e) {
      this.snack.open(e instanceof CallFailed ? e.message : 'Setting the secret failed.', 'Close');
    } finally {
      this.busy.set(false);
    }
  }

  protected async remove(s: Secret): Promise<void> {
    const used = this.usedBy(s);
    const ok = await this.confirm(
      `Delete ${s.name}?`,
      used.length
        ? `It's in use: ${used.join(', ')}. Those settings fail until it's set again.`
        : 'No setting references it. Its value is gone for good.',
      'Delete',
    );
    if (!ok) return;
    this.busy.set(true);
    try {
      await this.api.call('org.sparewall.Secrets.Delete', { name: s.name });
      this.snack.open(`Deleted ${s.name}.`, undefined, { duration: 4000 });
      this.secrets.reload();
    } catch (e) {
      this.snack.open(e instanceof CallFailed ? e.message : 'Deleting the secret failed.', 'Close');
    } finally {
      this.busy.set(false);
    }
  }

  protected checkPassword(): void {
    this.dialog.open(PasswordCheck, { width: '520px' });
  }

  protected readonly backupPassword = BACKUP_PASSWORD;

  private confirm(title: string, text: string, action: string): Promise<boolean | undefined> {
    return firstValueFrom(
      this.dialog
        .open<ConfirmDialog, ConfirmData, boolean>(ConfirmDialog, { data: { title, text, action } })
        .afterClosed(),
    );
  }
}
