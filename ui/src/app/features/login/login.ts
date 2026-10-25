import { Component, inject, signal } from '@angular/core';
import { FormField, form, required, submit } from '@angular/forms/signals';
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { Router } from '@angular/router';

import { CallFailed } from '../../api/api-client';
import { NeedsViewer, Session } from '../../core/session';

@Component({
  selector: 'app-login',
  imports: [
    FormField,
    MatButtonModule,
    MatCardModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
  ],
  templateUrl: './login.html',
  styleUrl: './login.scss',
})
export class Login {
  private readonly session = inject(Session);
  private readonly router = inject(Router);

  protected readonly model = signal({ user: '', password: '' });
  protected readonly loginForm = form(this.model, (p) => {
    required(p.user, { message: 'Enter your user name.' });
    required(p.password, { message: 'Enter your password.' });
  });
  protected readonly problem = signal('');
  /** Whether the password is shown as typed, to check it before signing in. */
  protected readonly showPassword = signal(false);

  protected signIn(): void {
    submit(this.loginForm, async () => {
      this.problem.set('');
      const { user, password } = this.model();
      try {
        await this.session.signIn(user, password);
        await this.router.navigate(['/']);
      } catch (e) {
        this.problem.set(message(e));
      }
    });
  }
}

function message(e: unknown): string {
  if (e instanceof NeedsViewer) return e.message;
  if (e instanceof CallFailed) {
    if (e.status === 401 || e.status === 403) return 'The user name or password is wrong.';
    if (e.status === 0 || e.status === 502) return 'The node did not answer. Try again.';
    return e.message;
  }
  return 'Signing in failed.';
}
