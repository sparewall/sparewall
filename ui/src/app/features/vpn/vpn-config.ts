import { Component, computed, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MAT_DIALOG_DATA, MatDialogModule } from '@angular/material/dialog';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatSelectModule } from '@angular/material/select';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';
import { renderSVG } from 'uqr';

import { ApiClient, CallFailed } from '../../api/api-client';

export interface VpnConfigData {
  instance: string;
  peer: string;
  /** The instance's listen port, then its extra ports. */
  ports: number[];
  /** A site-to-site peer: the configuration is the other site's. */
  site: boolean;
}

/** Offer `text` as a file named `name`. */
function saveFile(name: string, text: string, type: string): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  // Some browsers read the URL after click() returns: revoke it later.
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

/** A QR code of `text`, as SVG markup drawn in the browser (nothing leaves it). */
export function qrSvg(text: string): string {
  return renderSVG(text, { ecc: 'L', border: 4 });
}

/**
 * A peer's WireGuard configuration (#310), as `sparewall vpn client-config`
 * prints it: shown only once asked for, as it carries the peer's keys, then
 * offered as a `.conf` file and a QR code for the WireGuard mobile apps.
 */
@Component({
  selector: 'app-vpn-config',
  imports: [
    FormsModule,
    MatButtonModule,
    MatDialogModule,
    MatFormFieldModule,
    MatIconModule,
    MatSelectModule,
  ],
  template: `
    <h2 mat-dialog-title>{{ data.peer }} on {{ data.instance }}</h2>
    <mat-dialog-content>
      @if (!config()) {
        <p>
          {{
            data.site
              ? 'The other site’s configuration'
              : 'The configuration for ' + data.peer + '’s device'
          }}
          carries its private key{{ data.site ? '' : ' and preshared key' }}: anyone with it can
          connect as {{ data.peer }}. Reading it is logged, with who asked.
        </p>
        @if (data.ports.length > 1) {
          <mat-form-field>
            <mat-label>Port</mat-label>
            <mat-select [(ngModel)]="port" name="port">
              @for (p of data.ports; track p; let first = $first) {
                <mat-option [value]="p">{{ p }}{{ first ? ' (the listen port)' : '' }}</mat-option>
              }
            </mat-select>
            <mat-hint>Another port for networks that block the listen port.</mat-hint>
          </mat-form-field>
        }
      } @else {
        @if (!data.site) {
          <div class="qr" [innerHTML]="qr()" aria-label="QR code of the configuration"></div>
        }
        <pre>{{ config() }}</pre>
      }
      @if (failure(); as f) {
        <p class="error" role="alert">{{ f }}</p>
      }
    </mat-dialog-content>
    <mat-dialog-actions align="end">
      <button matButton type="button" mat-dialog-close>Close</button>
      @if (!config()) {
        <button matButton="filled" type="button" [disabled]="busy()" (click)="show()">
          Show the configuration
        </button>
      } @else {
        <button matButton="filled" type="button" (click)="download()">
          <mat-icon>download</mat-icon>
          {{ fileName() }}
        </button>
      }
    </mat-dialog-actions>
  `,
  styles: `
    pre {
      font: var(--mat-sys-body-small);
      font-family: monospace;
      background: var(--mat-sys-surface-container);
      padding: 8px;
      overflow-x: auto;
    }
    .qr {
      width: min(320px, 100%);
      margin: 0 auto 8px;
      background: white;
    }
    .error {
      color: var(--mat-sys-error);
    }
    mat-form-field {
      width: 100%;
    }
  `,
})
export class VpnConfig {
  protected readonly data = inject<VpnConfigData>(MAT_DIALOG_DATA);
  private readonly api = inject(ApiClient);
  private readonly sanitizer = inject(DomSanitizer);
  protected port = this.data.ports[0];
  protected readonly config = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly failure = signal<string | null>(null);
  /** The library's own SVG of the text, which holds nothing but the code. */
  protected readonly qr = computed<SafeHtml>(() => {
    const c = this.config();
    return c ? this.sanitizer.bypassSecurityTrustHtml(qrSvg(c)) : '';
  });
  protected readonly fileName = computed(() => `${this.data.instance}-${this.data.peer}.conf`);

  protected async show(): Promise<void> {
    this.busy.set(true);
    this.failure.set(null);
    try {
      const r = await this.api.call('org.sparewall.Firewall.VpnClientConfig', {
        instance: this.data.instance,
        peer: this.data.peer,
        port: this.port === this.data.ports[0] ? null : this.port,
      });
      this.config.set(r.config);
    } catch (e) {
      this.failure.set(
        e instanceof CallFailed ? e.message : 'The configuration could not be read.',
      );
    } finally {
      this.busy.set(false);
    }
  }

  protected download(): void {
    const c = this.config();
    if (c) saveFile(this.fileName(), c, 'text/plain');
  }
}
