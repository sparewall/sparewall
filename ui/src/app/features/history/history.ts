import { DatePipe } from '@angular/common';
import { httpResource } from '@angular/common/http';
import { Component, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { MatTooltipModule } from '@angular/material/tooltip';
import { firstValueFrom } from 'rxjs';

import { ApiClient, CallFailed, callUrl } from '../../api/api-client';
import { Reply, Schemas } from '../../api/api.model';
import { NodeEvents } from '../../core/node-events';
import { Session } from '../../core/session';
import { ConfirmRollback } from './confirm-rollback';

type Generation = Schemas['org.sparewall.Firewall.Generation'];

/** Every generation, newest first, and rolling back to one. */
@Component({
  selector: 'app-history',
  imports: [DatePipe, MatButtonModule, MatIconModule, MatTableModule, MatTooltipModule],
  templateUrl: './history.html',
  styleUrl: './history.scss',
})
export class History {
  private readonly api = inject(ApiClient);
  private readonly events = inject(NodeEvents);
  private readonly dialog = inject(MatDialog);
  private readonly snack = inject(MatSnackBar);
  protected readonly session = inject(Session);

  protected readonly history = httpResource<Reply<'org.sparewall.Firewall.History'>>(() => {
    this.events.count();
    return { url: callUrl('org.sparewall.Firewall.History'), method: 'POST', body: { limit: 50 } };
  });
  protected readonly columns = ['id', 'applied', 'author', 'summary', 'actions'];
  protected readonly busy = signal(false);
  /** Changed paths shown per generation; `sparewall history` has them all. */
  protected readonly shown = 6;

  protected async rollback(g: Generation, active: number): Promise<void> {
    const ok = await firstValueFrom(
      this.dialog.open(ConfirmRollback, { data: { generation: g, active } }).afterClosed(),
    );
    if (!ok) return;
    this.busy.set(true);
    try {
      const r = await this.api.call('org.sparewall.Firewall.Rollback', { id: g.id });
      this.snack.open(
        `Generation ${r.generation.id} runs generation ${g.id}'s configuration.`,
        undefined,
        { duration: 5000 },
      );
      this.history.reload();
    } catch (e) {
      this.snack.open(e instanceof CallFailed ? e.message : 'Rolling back failed.', 'Close');
    } finally {
      this.busy.set(false);
    }
  }
}
