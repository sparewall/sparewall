import { Component, inject, signal } from '@angular/core';
import { FormField, form, required, validate } from '@angular/forms/signals';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';

export interface NameData {
  title: string;
  name: string;
  /** Names already taken. */
  taken: string[];
}

/** Asks for a name not yet taken; closes with it, or nothing to cancel. */
@Component({
  selector: 'app-name-dialog',
  imports: [FormField, MatButtonModule, MatDialogModule, MatFormFieldModule, MatInputModule],
  template: `
    <h2 mat-dialog-title>{{ data.title }}</h2>
    <form (submit)="done(); $event.preventDefault()" novalidate>
      <mat-dialog-content>
        <mat-form-field>
          <mat-label>Name</mat-label>
          <input matInput cdkFocusInitial [formField]="nameForm.name" />
        </mat-form-field>
        @if (model().name && nameForm.name().invalid()) {
          <p class="error" role="alert">{{ nameForm.name().errors()[0].message }}</p>
        }
      </mat-dialog-content>
      <mat-dialog-actions align="end">
        <button matButton type="button" mat-dialog-close>Cancel</button>
        <button matButton="filled" type="submit" [disabled]="nameForm().invalid()">OK</button>
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
      margin: 0;
    }
  `,
})
export class NameDialog {
  protected readonly data = inject<NameData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<NameDialog, string>);
  protected readonly model = signal({ name: this.data.name });
  protected readonly nameForm = form(this.model, (p) => {
    required(p.name, { message: 'Give it a name.' });
    validate(p.name, ({ value }) => {
      const name = value().trim();
      return name !== this.data.name && this.data.taken.includes(name)
        ? { kind: 'taken', message: `${name} already exists.` }
        : undefined;
    });
  });

  protected done(): void {
    if (this.nameForm().invalid()) return;
    this.ref.close(this.model().name.trim());
  }
}
