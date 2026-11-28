import { Component, inject, signal } from '@angular/core';
import { FormField, form, required, validate } from '@angular/forms/signals';
import { MatButtonModule } from '@angular/material/button';
import { MatCheckboxModule } from '@angular/material/checkbox';
import { MAT_DIALOG_DATA, MatDialogModule, MatDialogRef } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';

import { secretNameOk } from './references';

export interface SecretData {
  /** Replacing this secret; absent to add one. */
  name?: string;
  /** The node is one of a pair: a secret is the cluster's unless asked. */
  pair: boolean;
}

export interface SecretResult {
  name: string;
  value: string;
  cluster: boolean;
}

/** A secret's name and value: entered twice, never shown again. */
@Component({
  selector: 'app-secret-dialog',
  imports: [
    FormField,
    MatButtonModule,
    MatCheckboxModule,
    MatDialogModule,
    MatFormFieldModule,
    MatInputModule,
  ],
  template: `
    <h2 mat-dialog-title>{{ data.name ? 'Replace ' + data.name : 'Add a secret' }}</h2>
    <form (submit)="done(); $event.preventDefault()" novalidate>
      <mat-dialog-content>
        @if (!data.name) {
          <mat-form-field>
            <mat-label>Name</mat-label>
            <input matInput autocomplete="off" cdkFocusInitial [formField]="secretForm.name" />
            <mat-hint>Settings reference it as secret:name.</mat-hint>
          </mat-form-field>
        }
        <mat-form-field>
          <mat-label>Value</mat-label>
          <input
            matInput
            type="password"
            autocomplete="new-password"
            [formField]="secretForm.value"
          />
        </mat-form-field>
        <mat-form-field>
          <mat-label>Value again</mat-label>
          <input
            matInput
            type="password"
            autocomplete="new-password"
            [formField]="secretForm.again"
          />
        </mat-form-field>
        @if (data.pair) {
          <mat-checkbox [formField]="secretForm.cluster">The pair's, on both nodes</mat-checkbox>
        }
        <p class="hint">
          It can't be read back, by anyone.
          @if (data.name) {
            Replacing it gives it a new version.
          }
        </p>
        @for (f of [secretForm.name, secretForm.value, secretForm.again]; track $index) {
          @if (f().dirty() && f().errors()[0]; as e) {
            <p class="error" role="alert">{{ e.message }}</p>
          }
        }
      </mat-dialog-content>
      <mat-dialog-actions align="end">
        <button matButton type="button" mat-dialog-close>Cancel</button>
        <button matButton="filled" type="submit" [disabled]="secretForm().invalid()">
          {{ data.name ? 'Replace' : 'Add' }}
        </button>
      </mat-dialog-actions>
    </form>
  `,
  styles: `
    mat-form-field {
      width: 100%;
    }
    .hint {
      color: var(--mat-sys-on-surface-variant);
      font: var(--mat-sys-body-small);
    }
    .error {
      color: var(--mat-sys-error);
      font: var(--mat-sys-body-small);
    }
  `,
})
export class SecretDialog {
  protected readonly data = inject<SecretData>(MAT_DIALOG_DATA);
  private readonly ref = inject(MatDialogRef<SecretDialog, SecretResult>);
  protected readonly model = signal({
    name: this.data.name ?? '',
    value: '',
    again: '',
    cluster: true,
  });
  protected readonly secretForm = form(this.model, (p) => {
    required(p.name, { message: 'Give the secret a name.' });
    validate(p.name, ({ value }) =>
      secretNameOk(value().trim())
        ? undefined
        : {
            kind: 'name',
            message: 'Up to 64 letters, digits, ., _ and -, starting with a letter or digit.',
          },
    );
    required(p.value, { message: 'Enter the value.' });
    validate(p.again, ({ value, valueOf }) =>
      value() === valueOf(p.value) ? undefined : { kind: 'differ', message: 'The values differ.' },
    );
  });

  protected done(): void {
    if (this.secretForm().invalid()) return;
    const { name, value, cluster } = this.model();
    this.ref.close({ name: name.trim(), value, cluster: !this.data.pair || cluster });
  }
}
