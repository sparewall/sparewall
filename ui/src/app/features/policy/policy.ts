import { Component, computed, inject } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatTooltipModule } from '@angular/material/tooltip';
import { JsonSchema7 } from '@jsonforms/core';
import { firstValueFrom } from 'rxjs';

import { DraftPage } from '../config/draft-page';
import { Cell, matrix, natLabel, withPolicy, zones } from './matrix';
import { PolicyData, PolicyDialog, PolicyResult } from './policy-dialog';

/**
 * The zone policy matrix (design: "The UI"): from each zone (rows) to
 * each zone (columns), what the firewall does, and editing a pair's
 * policy. Edits collect in a draft, reviewed and applied together.
 */
@Component({
  selector: 'app-policy',
  imports: [MatButtonModule, MatIconModule, MatTooltipModule],
  templateUrl: './policy.html',
  styleUrl: './policy.scss',
})
export class PolicyMatrix extends DraftPage {
  private readonly dialog = inject(MatDialog);

  protected readonly zones = computed(() => {
    const d = this.draft();
    return d ? zones(d) : [];
  });
  protected readonly rows = computed(() => {
    const d = this.draft();
    return d ? matrix(d) : [];
  });
  /** Pairs whose policy differs from the active document's. */
  protected readonly edited = computed(() => {
    const d = this.draft();
    const was = this.current.hasValue() ? this.current.value().config.policy : undefined;
    const now = d?.policy ?? {};
    const keys = new Set([...Object.keys(was ?? {}), ...Object.keys(now)]);
    return new Set([...keys].filter((k) => JSON.stringify(was?.[k]) !== JSON.stringify(now[k])));
  });
  protected readonly natLabel = natLabel;

  protected rulesCount(c: Cell): number {
    return Object.keys(c.policy?.rules ?? {}).length;
  }

  protected async open(c: Cell): Promise<void> {
    const schema = this.schema()?.properties?.['policy']?.additionalProperties as
      JsonSchema7 | undefined;
    const d = this.draft();
    if (!schema || !d || c.none) return;
    const r = await firstValueFrom(
      this.dialog
        .open<PolicyDialog, PolicyData, PolicyResult>(PolicyDialog, {
          data: {
            key: c.key,
            policy: c.policy,
            fallback: c.fallback,
            schema,
            readonly: !this.session.can('operator'),
          },
          width: '720px',
          maxHeight: '90vh',
        })
        .afterClosed(),
    );
    if (!r) return;
    this.draft.set(withPolicy(d, c.key, 'remove' in r ? undefined : r.policy));
  }
}
