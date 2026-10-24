import { Component, inject, signal } from '@angular/core';
import { FormField, form, min, required, validate } from '@angular/forms/signals';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';

import { ROLES } from '../../shared/roles';

export interface TokenResult {
  name: string;
  role: string;
  /** 0: never expires. */
  expiresDays: number;
}

/** A new API token's name, role and lifetime. */
@Component({
  selector: 'app-token-dialog',
  imports: [
    FormField,
    MatButtonModule,
    MatDialogModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
  ],
  template: `
    <h2 mat-dialog-title>Create an API token</h2>
    <form (submit)="done(); $event.preventDefault()" novalidate>
      <mat-dialog-content>
        <mat-form-field>
          <mat-label>Name</mat-label>
          <input matInput autocomplete="off" cdkFocusInitial [formField]="tokenForm.name" />
          <mat-hint>What uses it, e.g. prometheus or ci.</mat-hint>
        </mat-form-field>
        <mat-form-field>
          <mat-label>Role</mat-label>
          <mat-select [formField]="tokenForm.role">
            @for (r of roles; track r.role) {
              <mat-option [value]="r.role">{{ r.role }}: {{ r.does }}</mat-option>
            }
          </mat-select>
        </mat-form-field>
        <mat-form-field>
          <mat-label>Expires after (days)</mat-label>
          <input matInput type="number" [formField]="tokenForm.expiresDays" />
          <mat-hint>0: never.</mat-hint>
        </mat-form-field>
        @if (tokenForm.name().dirty() && tokenForm.name().errors()[0]; as e) {
          <p class="error" role="alert">{{ e.message }}</p>
        }
      </mat-dialog-content>
      <mat-dialog-actions align="end">
        <button matButton type="button" mat-dialog-close>Cancel</button>
        <button matButton="filled" type="submit" [disabled]="tokenForm().invalid()">Create</button>
      </mat-dialog-actions>
    </form>
  `,
  styles: `
    mat-form-field {
      width: 100%;
    }
    .error {
      color: var(--mat-sys-error);
      font: var(--mat-sys-body-small);
    }
  `,
})
export class TokenDialog {
  private readonly taken = inject<string[]>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<TokenDialog, TokenResult>);
  protected readonly roles = ROLES;
  protected readonly model = signal({ name: '', role: 'monitor', expiresDays: 0 });
  protected readonly tokenForm = form(this.model, (p) => {
    required(p.name, { message: 'Give the token a name.' });
    validate(p.name, ({ value }) =>
      this.taken.includes(value().trim())
        ? { kind: 'taken', message: `A token named ${value().trim()} exists.` }
        : undefined,
    );
    min(p.expiresDays, 0);
  });

  protected done(): void {
    if (this.tokenForm().invalid()) return;
    const { name, role, expiresDays } = this.model();
    this.ref.close({ name: name.trim(), role, expiresDays });
  }
}
