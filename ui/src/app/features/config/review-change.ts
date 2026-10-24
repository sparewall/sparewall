import { Component, inject, signal } from '@angular/core';
import { FormField, form, min } from '@angular/forms/signals';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';

import { Reply } from '../../api/api.model';

export interface ReviewData {
  preview: Reply<'org.sparewall.Firewall.Apply'>;
  base: number;
}

/**
 * What a change does (the node's dry run), and the window to confirm it in
 * before the node reverts it by itself. Closes with the seconds, or
 * nothing to cancel.
 */
@Component({
  selector: 'app-review-change',
  imports: [FormField, MatButtonModule, MatDialogModule, MatFormFieldModule, MatInputModule],
  templateUrl: './review-change.html',
  styleUrl: './review-change.scss',
})
export class ReviewChange {
  protected readonly data = inject<ReviewData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<ReviewChange, number>);
  /** Long enough to check the change from the UI, short enough to revert soon if it cut you off. */
  protected readonly model = signal({ confirmSeconds: 120 });
  protected readonly window = form(this.model, (p) => {
    min(p.confirmSeconds, 0);
  });

  /** The window as it is when Apply is pressed. */
  protected apply(): void {
    if (this.window().invalid()) return;
    this.ref.close(this.model().confirmSeconds);
  }
}
