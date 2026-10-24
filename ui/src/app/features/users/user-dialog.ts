import { Component, inject, signal } from '@angular/core';
import { FormField, form, minLength, required, validate } from '@angular/forms/signals';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';

import { ROLES } from '../../shared/roles';

export interface UserData {
  /** A user to change, or none to add one. */
  name?: string;
  role?: string;
  /** Change only the password. */
  passwordOnly?: boolean;
  taken: string[];
}

export interface UserResult {
  name: string;
  role: string;
  /** Empty: keep the password. */
  password: string;
}

/** Adding a user, or changing one's role or password. */
@Component({
  selector: 'app-user-dialog',
  imports: [
    FormField,
    MatButtonModule,
    MatDialogModule,
    MatFormFieldModule,
    MatInputModule,
    MatSelectModule,
  ],
  templateUrl: './user-dialog.html',
  styles: `
    mat-form-field {
      width: 100%;
    }
    .error {
      color: var(--mat-sys-error);
      font: var(--mat-sys-body-small);
      margin: 0 0 8px;
    }
  `,
})
export class UserDialog {
  protected readonly data = inject<UserData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<UserDialog, UserResult>);
  protected readonly roles = ROLES;
  protected readonly adding = this.data.name === undefined;

  protected readonly model = signal({
    name: this.data.name ?? '',
    role: this.data.role ?? 'viewer',
    password: '',
    again: '',
  });
  protected readonly userForm = form(this.model, (p) => {
    required(p.name, { message: 'Give the user a name.' });
    validate(p.name, ({ value }) => {
      const n = value().trim();
      if (this.adding && this.data.taken.includes(n)) {
        return { kind: 'taken', message: `${n} already exists.` };
      }
      // The node's rule (sparewall-core users.rs).
      return /^[a-z][a-z0-9_-]*$/.test(n) || n === ''
        ? undefined
        : {
            kind: 'name',
            message: 'Lower-case letters, digits, - and _, starting with a letter.',
          };
    });
    // A new user needs a password; a change may keep it.
    required(p.password, {
      message: 'Give the user a password.',
      when: () => this.adding || !!this.data.passwordOnly,
    });
    minLength(p.password, 8, { message: 'At least 8 characters.' });
    validate(p.again, ({ value, valueOf }) =>
      value() === valueOf(p.password)
        ? undefined
        : { kind: 'again', message: 'The passwords differ.' },
    );
  });

  protected firstError(): string | undefined {
    for (const f of [this.userForm.name, this.userForm.password, this.userForm.again]) {
      const e = f().errors()[0];
      if (e && (f().dirty() || f().touched())) return e.message;
    }
    return undefined;
  }

  protected done(): void {
    if (this.userForm().invalid()) return;
    const { name, role, password } = this.model();
    this.ref.close({ name: name.trim(), role, password });
  }
}
