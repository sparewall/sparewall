import { DatePipe } from '@angular/common';
import { httpResource } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { firstValueFrom } from 'rxjs';

import { ApiClient, CallFailed, callUrl } from '../../api/api-client';
import { Reply, Schemas } from '../../api/api.model';
import { ConfirmData, ConfirmDialog } from '../../shared/confirm-dialog';
import { NewToken, NewTokenData } from './new-token';
import { TokenDialog, TokenResult } from './token-dialog';

type Token = Schemas['org.sparewall.Auth.TokenInfo'];

/** API tokens for scripts and monitoring (admin only). */
@Component({
  selector: 'app-tokens',
  imports: [DatePipe, MatButtonModule, MatIconModule, MatTableModule],
  templateUrl: './tokens.html',
  styles: `
    table {
      width: 100%;
    }
    .never {
      color: var(--mat-sys-on-surface-variant);
    }
    .problem {
      color: var(--mat-sys-error);
    }
  `,
})
export class Tokens {
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(MatDialog);
  private readonly snack = inject(MatSnackBar);

  protected readonly tokens = httpResource<Reply<'org.sparewall.Auth.ListTokens'>>(() => ({
    url: callUrl('org.sparewall.Auth.ListTokens'),
    method: 'POST',
    body: {},
  }));
  protected readonly columns = ['name', 'role', 'created', 'expires', 'last_used', 'actions'];
  protected readonly busy = signal(false);

  protected expiry(t: Token): Date | undefined {
    return t.expires ? new Date(t.expires * 1000) : undefined;
  }

  protected async create(): Promise<void> {
    const taken = this.tokens.hasValue() ? this.tokens.value().tokens.map((t) => t.name) : [];
    const r = await firstValueFrom(
      this.dialog
        .open<TokenDialog, string[], TokenResult>(TokenDialog, { data: taken, width: '480px' })
        .afterClosed(),
    );
    if (!r) return;
    this.busy.set(true);
    try {
      const created = await this.api.call('org.sparewall.Auth.CreateToken', {
        name: r.name,
        role: r.role,
        expires_days: r.expiresDays || null,
      });
      this.tokens.reload();
      this.dialog.open<NewToken, NewTokenData>(NewToken, {
        data: { name: r.name, token: created.token },
        width: '560px',
        disableClose: true,
      });
    } catch (e) {
      this.snack.open(e instanceof CallFailed ? e.message : 'Creating the token failed.', 'Close');
    } finally {
      this.busy.set(false);
    }
  }

  protected async revoke(t: Token): Promise<void> {
    const ok = await firstValueFrom(
      this.dialog
        .open<ConfirmDialog, ConfirmData, boolean>(ConfirmDialog, {
          data: {
            title: `Revoke ${t.name}?`,
            text: 'It stops working at once, also on connections already using it.',
            action: 'Revoke',
          },
        })
        .afterClosed(),
    );
    if (!ok) return;
    this.busy.set(true);
    try {
      await this.api.call('org.sparewall.Auth.RevokeToken', { name: t.name });
      this.snack.open(`Revoked ${t.name}.`, undefined, { duration: 4000 });
      this.tokens.reload();
    } catch (e) {
      this.snack.open(e instanceof CallFailed ? e.message : 'Revoking failed.', 'Close');
    } finally {
      this.busy.set(false);
    }
  }
}
