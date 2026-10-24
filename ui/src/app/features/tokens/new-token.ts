import { Clipboard } from '@angular/cdk/clipboard';
import { Component, inject, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';

export interface NewTokenData {
  name: string;
  token: string;
}

/** The new token's value, shown this once: the node keeps only its hash. */
@Component({
  selector: 'app-new-token',
  imports: [MatButtonModule, MatDialogModule, MatIconModule],
  template: `
    <h2 mat-dialog-title>Token {{ data.name }}</h2>
    <mat-dialog-content>
      <p>Copy it now. It is not shown again: the node keeps only its hash.</p>
      <code class="token">{{ data.token }}</code>
      <p>
        Use it as <code>Authorization: Bearer &lt;token&gt;</code>, or SPAREWALL_TOKEN for the CLI.
      </p>
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button matButton (click)="copy()">
        <mat-icon>{{ copied() ? 'check' : 'content_copy' }}</mat-icon>
        {{ copied() ? 'Copied' : 'Copy' }}
      </button>
      <button matButton="filled" mat-dialog-close>Done</button>
    </mat-dialog-actions>
  `,
  styles: `
    .token {
      display: block;
      padding: 8px;
      border-radius: 8px;
      background: var(--mat-sys-surface-container-high);
      overflow-wrap: anywhere;
      user-select: all;
    }
  `,
})
export class NewToken {
  protected readonly data = inject<NewTokenData>(MAT_DIALOG_DATA);
  private readonly clipboard = inject(Clipboard);
  protected readonly copied = signal(false);

  protected copy(): void {
    this.copied.set(this.clipboard.copy(this.data.token));
  }
}
