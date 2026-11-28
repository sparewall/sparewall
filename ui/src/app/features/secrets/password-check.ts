import { Component, inject, signal } from '@angular/core';
import { FormField, form, required } from '@angular/forms/signals';
import { MatButtonModule } from '@angular/material/button';
import { MatDialogModule } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';

import { ApiClient, CallFailed } from '../../api/api-client';
import { Reply } from '../../api/api.model';

/**
 * Check a candidate against the stored backup password and the newest
 * bundle, as `sparewall backup --check-password` does (#142).
 */
@Component({
  selector: 'app-password-check',
  imports: [FormField, MatButtonModule, MatDialogModule, MatFormFieldModule, MatInputModule],
  template: `
    <h2 mat-dialog-title>Check the backup password</h2>
    <form (submit)="check(); $event.preventDefault()" novalidate>
      <mat-dialog-content>
        <p class="hint">
          Whether a password is the stored one, and opens the secrets sealed in the newest backup:
          the one a restore will ask for.
        </p>
        <mat-form-field>
          <mat-label>Password</mat-label>
          <input
            matInput
            type="password"
            autocomplete="off"
            cdkFocusInitial
            [formField]="checkForm.password"
          />
        </mat-form-field>
        @if (result(); as r) {
          <ul class="result" role="status">
            <li>
              {{
                r.matches_stored
                  ? 'It is the stored backup password.'
                  : 'It is not the stored backup password.'
              }}
            </li>
            @if (r.bundle) {
              @if (r.opens_bundle === true) {
                <li>
                  It opens the secrets in {{ r.bundle }}: {{ r.secrets.join(', ') || 'none' }}.
                </li>
              } @else if (r.opens_bundle === false) {
                <li>It doesn't open the secrets in {{ r.bundle }}.</li>
              }
            }
            @for (n of r.notes; track n) {
              <li>{{ n }}</li>
            }
          </ul>
        }
        @if (failure(); as f) {
          <p class="error" role="alert">{{ f }}</p>
        }
      </mat-dialog-content>
      <mat-dialog-actions align="end">
        <button matButton type="button" mat-dialog-close>Close</button>
        <button matButton="filled" type="submit" [disabled]="checkForm().invalid() || busy()">
          Check
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
    }
  `,
})
export class PasswordCheck {
  private readonly api = inject(ApiClient);
  protected readonly model = signal({ password: '' });
  protected readonly checkForm = form(this.model, (p) => {
    required(p.password, { message: 'Enter the password.' });
  });
  protected readonly result = signal<Reply<'org.sparewall.Secrets.CheckBackupPassword'> | null>(
    null,
  );
  protected readonly failure = signal<string | null>(null);
  protected readonly busy = signal(false);

  protected async check(): Promise<void> {
    if (this.checkForm().invalid()) return;
    this.busy.set(true);
    this.failure.set(null);
    this.result.set(null);
    try {
      this.result.set(
        await this.api.call('org.sparewall.Secrets.CheckBackupPassword', {
          password: this.model().password,
        }),
      );
    } catch (e) {
      this.failure.set(e instanceof CallFailed ? e.message : 'The check failed.');
    } finally {
      this.busy.set(false);
    }
  }
}
