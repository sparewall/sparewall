import { Service, inject } from '@angular/core';
import { MatDialog } from '@angular/material/dialog';
import { MatSnackBar } from '@angular/material/snack-bar';
import { firstValueFrom } from 'rxjs';

import { ApiClient, CallFailed } from '../../api/api-client';
import { Schemas } from '../../api/api.model';
import { ReviewChange, ReviewData } from './review-change';

type Document = Schemas['Document'];

/** How a review ended: applied, cancelled, or refused with the node's reasons. */
export type Outcome = { applied: true } | { applied: false; problems: string[] };

/**
 * Applying an edited document, wherever it was edited (the editor, the
 * policy matrix): the node's dry run first, shown for review with the
 * window to confirm in, then the apply itself on the same base generation.
 */
@Service()
export class ConfigChanges {
  private readonly api = inject(ApiClient);
  private readonly dialog = inject(MatDialog);
  private readonly snack = inject(MatSnackBar);

  async review(draft: Document, base: number): Promise<Outcome> {
    try {
      const preview = await this.api.call('org.sparewall.Firewall.Apply', {
        config: draft,
        base,
        dry_run: true,
      });
      const data: ReviewData = { preview, base };
      const confirmSeconds = await firstValueFrom(
        this.dialog.open(ReviewChange, { data, width: '640px' }).afterClosed(),
      );
      if (confirmSeconds === undefined) return { applied: false, problems: [] };
      const r = await this.api.call('org.sparewall.Firewall.Apply', {
        config: draft,
        base,
        confirm_seconds: confirmSeconds,
      });
      this.snack.open(
        r.confirm_seconds
          ? `Generation ${r.generation.id} applied: confirm it within ${r.confirm_seconds} s, or it reverts.`
          : `Generation ${r.generation.id} applied.`,
        undefined,
        { duration: 6000 },
      );
      return { applied: true };
    } catch (e) {
      return { applied: false, problems: problems(e) };
    }
  }
}

function problems(e: unknown): string[] {
  if (e instanceof CallFailed && e.reply?.error === 'org.sparewall.Firewall.ValidationFailed') {
    return e.reply.parameters.errors;
  }
  if (e instanceof CallFailed && e.status === 409) {
    return [
      `${e.message.replace(/\.?$/, '.')} Discard your changes to start again from the current configuration.`,
    ];
  }
  return [e instanceof CallFailed ? e.message : 'Applying failed.'];
}
