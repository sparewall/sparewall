import { Component, Injector, inject, input, signal } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatMenuModule } from '@angular/material/menu';
import { MatSnackBar } from '@angular/material/snack-bar';

import { ApiClient, CallFailed } from '../api/api-client';
import { NodeStatus } from '../core/node-status';

export type ExportFormat = 'yaml' | 'json';

/** The file `sparewall export` would write: `sparewall-<node>-gen<N>.<ext>`. */
export function exportName(
  node: string | undefined,
  generation: number,
  format: ExportFormat,
): string {
  return `sparewall-${node ?? 'node'}-gen${generation}.${format}`;
}

/** Offer `text` as a file named `name`. */
export function saveFile(name: string, text: string, type: string): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  // Some browsers read the URL after click() returns: revoke it later.
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

/**
 * Export a generation's document (#312), as YAML or JSON. The node writes
 * the text, as `sparewall export` does, so the file is the same, byte for
 * byte; secrets are by reference only.
 */
@Component({
  selector: 'app-export-menu',
  imports: [MatButtonModule, MatIconModule, MatMenuModule],
  template: `
    <button matButton [disabled]="busy()" [matMenuTriggerFor]="formats" [attr.aria-label]="label()">
      <mat-icon>download</mat-icon>
      Export
    </button>
    <mat-menu #formats="matMenu">
      <button mat-menu-item (click)="export('yaml')">YAML</button>
      <button mat-menu-item (click)="export('json')">JSON</button>
    </mat-menu>
  `,
})
export class ExportMenu {
  private readonly api = inject(ApiClient);
  // The node's name, for the file: looked up when saving, as the frame
  // around the pages already reads the status.
  private readonly injector = inject(Injector);
  private readonly snack = inject(MatSnackBar);
  /** The generation to export. */
  readonly generation = input.required<number>();
  protected readonly busy = signal(false);

  protected label(): string {
    return `Export generation ${this.generation()}`;
  }

  protected async export(format: ExportFormat): Promise<void> {
    this.busy.set(true);
    try {
      const r = await this.api.call('org.sparewall.Firewall.Export', {
        id: this.generation(),
        format,
      });
      if (r.text == null)
        throw new Error('The node did not format the document: it may be older than 0.9.0.');
      saveFile(
        exportName(this.injector.get(NodeStatus).node(), this.generation(), format),
        r.text,
        format === 'json' ? 'application/json' : 'application/yaml',
      );
    } catch (e) {
      this.snack.open(
        e instanceof CallFailed || e instanceof Error ? e.message : 'The export failed.',
        'Close',
      );
    } finally {
      this.busy.set(false);
    }
  }
}
