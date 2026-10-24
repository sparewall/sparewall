import { Component, inject } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule } from '@angular/material/dialog';

import { Schemas } from '../../api/api.model';

export interface RollbackData {
  generation: Schemas['org.sparewall.Firewall.Generation'];
  active: number;
}

@Component({
  selector: 'app-confirm-rollback',
  imports: [MatButtonModule, MatDialogModule],
  template: `
    <h2 mat-dialog-title>Roll back to generation {{ data.generation.id }}?</h2>
    <mat-dialog-content>
      <p>
        The node will run generation {{ data.generation.id }}'s configuration as a new generation,
        replacing generation {{ data.active }}. Its history is kept.
      </p>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button matButton mat-dialog-close>Cancel</button>
      <button matButton="filled" [mat-dialog-close]="true">Roll back</button>
    </mat-dialog-actions>
  `,
})
export class ConfirmRollback {
  protected readonly data = inject<RollbackData>(MAT_DIALOG_DATA);
}
