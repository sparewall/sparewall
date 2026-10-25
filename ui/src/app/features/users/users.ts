import { DatePipe } from '@angular/common';
import { httpResource } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatMenuModule } from '@angular/material/menu';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { firstValueFrom } from 'rxjs';

import { ApiClient, CallFailed, callUrl } from '../../api/api-client';
import { Reply, Schemas } from '../../api/api.model';
import { Session } from '../../core/session';
import { ConfirmData, ConfirmDialog } from '../../shared/confirm-dialog';
import { hashPassword } from '../../shared/sha512-crypt';
import { UserData, UserDialog, UserResult } from './user-dialog';

type User = Schemas['org.sparewall.Auth.UserInfo'];

/** The named users people sign in as, and their roles (admin only). */
@Component({
  selector: 'app-users',
  imports: [DatePipe, MatButtonModule, MatIconModule, MatMenuModule, MatTableModule],
  templateUrl: './users.html',
  styles: `
    table {
      width: 100%;
    }
    .locked {
      color: var(--mat-sys-on-surface-variant);
    }
    .problem {
      color: var(--mat-sys-error);
    }
  `,
})
export class Users {
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(MatDialog);
  private readonly snack = inject(MatSnackBar);
  protected readonly session = inject(Session);

  protected readonly users = httpResource<Reply<'org.sparewall.Auth.ListUsers'>>(() => ({
    url: callUrl('org.sparewall.Auth.ListUsers'),
    method: 'POST',
    body: {},
  }));
  protected readonly columns = ['name', 'role', 'updated', 'actions'];
  protected readonly busy = signal(false);

  private names(): string[] {
    return this.users.hasValue() ? this.users.value().users.map((u) => u.name) : [];
  }

  private ask(data: UserData): Promise<UserResult | undefined> {
    return firstValueFrom(
      this.dialog
        .open<UserDialog, UserData, UserResult>(UserDialog, { data, width: '480px' })
        .afterClosed(),
    );
  }

  protected async add(): Promise<void> {
    const r = await this.ask({ taken: this.names() });
    if (r) await this.set(r.name, r.role, r.password, `Added ${r.name} (${r.role}).`);
  }

  protected async changeRole(u: User): Promise<void> {
    const r = await this.ask({ name: u.name, role: u.role, taken: [] });
    if (r && r.role !== u.role) await this.set(u.name, r.role, '', `${u.name} is now ${r.role}.`);
  }

  protected async changePassword(u: User): Promise<void> {
    const r = await this.ask({ name: u.name, role: u.role, passwordOnly: true, taken: [] });
    if (r)
      await this.set(u.name, u.role, r.password, `Set ${u.name}'s password; its sessions ended.`);
  }

  protected async lock(u: User): Promise<void> {
    if (
      !(await this.confirm(
        `Lock ${u.name}?`,
        'It can no longer sign in, and its sessions end. A new password unlocks it.',
        'Lock',
      ))
    )
      return;
    await this.call(
      () =>
        this.api.call('org.sparewall.Auth.SetUser', {
          name: u.name,
          role: u.role,
          password_hash: '!',
        }),
      `Locked ${u.name}.`,
    );
  }

  protected async remove(u: User): Promise<void> {
    if (!(await this.confirm(`Remove ${u.name}?`, 'Its sessions end at once.', 'Remove'))) return;
    await this.call(
      () => this.api.call('org.sparewall.Auth.RemoveUser', { name: u.name }),
      `Removed ${u.name}.`,
    );
  }

  private async set(name: string, role: string, password: string, done: string): Promise<void> {
    await this.call(async () => {
      // Hashed here: the password itself never leaves the browser.
      const password_hash = password ? await hashPassword(password) : '';
      return this.api.call('org.sparewall.Auth.SetUser', { name, role, password_hash });
    }, done);
  }

  private confirm(title: string, text: string, action: string): Promise<boolean | undefined> {
    return firstValueFrom(
      this.dialog
        .open<ConfirmDialog, ConfirmData, boolean>(ConfirmDialog, { data: { title, text, action } })
        .afterClosed(),
    );
  }

  private async call(f: () => Promise<unknown>, done: string): Promise<void> {
    this.busy.set(true);
    try {
      await f();
      this.snack.open(done, undefined, { duration: 4000 });
      this.users.reload();
    } catch (e) {
      this.snack.open(e instanceof CallFailed ? e.message : 'That failed.', 'Close');
    } finally {
      this.busy.set(false);
    }
  }
}
