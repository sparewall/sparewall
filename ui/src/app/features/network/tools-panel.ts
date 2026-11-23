import { Component, DestroyRef, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';

import { ApiClient, CallFailed } from '../../api/api-client';

export type Tool = 'ping' | 'traceroute' | 'lookup';

export const RECORDS = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TXT', 'CAA'];

/** ping, traceroute and lookups from the node, their output as it comes (#264). */
@Component({
  selector: 'app-tools-panel',
  imports: [FormsModule, MatButtonModule, MatFormFieldModule, MatInputModule, MatSelectModule],
  template: `
    <form class="tool" (ngSubmit)="run()">
      <mat-form-field subscriptSizing="dynamic">
        <mat-label>Tool</mat-label>
        <mat-select [(ngModel)]="tool" name="tool">
          <mat-option value="ping">ping</mat-option>
          <mat-option value="traceroute">traceroute</mat-option>
          <mat-option value="lookup">DNS lookup</mat-option>
        </mat-select>
      </mat-form-field>
      <mat-form-field subscriptSizing="dynamic" class="grow">
        <mat-label>{{ tool === 'lookup' ? 'Name or address' : 'Host' }}</mat-label>
        <input matInput [(ngModel)]="target" name="target" required maxlength="253" />
      </mat-form-field>
      @if (tool === 'lookup') {
        <mat-form-field subscriptSizing="dynamic" class="small">
          <mat-label>Record</mat-label>
          <mat-select [(ngModel)]="record" name="record">
            @for (r of records; track r) {
              <mat-option [value]="r">{{ r }}</mat-option>
            }
          </mat-select>
        </mat-form-field>
        <mat-form-field subscriptSizing="dynamic" floatLabel="always">
          <mat-label>Server</mat-label>
          <input
            matInput
            [(ngModel)]="server"
            name="server"
            placeholder="Default"
            title="Leave empty to ask the node's own resolver"
          />
        </mat-form-field>
      } @else {
        <mat-form-field subscriptSizing="dynamic">
          <mat-label>From</mat-label>
          <mat-select [(ngModel)]="from" name="from">
            <mat-option [value]="''">By the routes</mat-option>
            @for (n of networks(); track n) {
              <mat-option [value]="n">{{ n }}</mat-option>
            }
          </mat-select>
        </mat-form-field>
      }
      @if (tool === 'ping') {
        <mat-form-field subscriptSizing="dynamic" class="small">
          <mat-label>Count</mat-label>
          <input matInput type="number" min="1" max="10" [(ngModel)]="count" name="count" />
        </mat-form-field>
      }
      @if (running()) {
        <button mat-stroked-button type="button" (click)="stop()">Stop</button>
      } @else {
        <button mat-flat-button type="submit" [disabled]="!target.trim()">Run</button>
      }
    </form>
    @if (problem(); as p) {
      <p class="problem" role="alert">{{ p }}</p>
    }
    @if (output().length || exit() !== null) {
      <pre aria-live="polite" data-testid="output">{{ output().join('\\n') }}</pre>
      @if (exit(); as e) {
        <p class="exit">Exited with status {{ e }}.</p>
      }
    }
  `,
  styles: `
    .tool {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px 12px;
      margin: 8px 0;

      mat-form-field {
        width: 180px;
      }
      .grow {
        flex: 1 1 220px;
      }
      .small {
        width: 100px;
      }
    }
    pre {
      margin: 0 0 8px;
      padding: 8px 12px;
      border-radius: 8px;
      background: var(--mat-sys-surface-container);
      font: var(--mat-sys-body-small);
      font-family: monospace;
      white-space: pre-wrap;
      overflow-wrap: anywhere;
      max-height: 480px;
      overflow: auto;
    }
    .problem {
      color: var(--mat-sys-error);
    }
    .exit {
      color: var(--mat-sys-on-surface-variant);
    }
  `,
})
export class ToolsPanel {
  private readonly api = inject(ApiClient);

  /** The networks to leave from. */
  readonly networks = input<string[]>([]);
  /** The pair's other node, to run the tool on through this one (#268). */
  readonly node = input<string | null>(null);

  protected readonly records = RECORDS;
  protected tool: Tool = 'ping';
  protected target = '';
  protected from = '';
  protected count = 4;
  protected record = 'A';
  protected server = '';

  protected readonly output = signal<string[]>([]);
  protected readonly exit = signal<number | null>(null);
  protected readonly running = signal(false);
  protected readonly problem = signal<string | null>(null);
  private abort: AbortController | null = null;

  constructor() {
    inject(DestroyRef).onDestroy(() => this.abort?.abort());
  }

  /** The call for the form as it is. */
  call(): { method: string; params: Record<string, unknown> } {
    const t = this.target.trim();
    const node = this.node();
    switch (this.tool) {
      case 'ping':
        return {
          method: 'org.sparewall.Diagnostics.Ping',
          params: { host: t, network: this.from || null, count: this.count || null, node },
        };
      case 'traceroute':
        return {
          method: 'org.sparewall.Diagnostics.Traceroute',
          params: { host: t, network: this.from || null, node },
        };
      case 'lookup':
        return {
          method: 'org.sparewall.Diagnostics.Lookup',
          params: { name: t, record: this.record, server: this.server.trim() || null, node },
        };
    }
  }

  async run(): Promise<void> {
    if (!this.target.trim() || this.running()) return;
    this.abort?.abort();
    const abort = new AbortController();
    this.abort = abort;
    this.output.set([]);
    this.exit.set(null);
    this.problem.set(null);
    this.running.set(true);
    const { method, params } = this.call();
    try {
      for await (const r of this.api.stream(method as never, params as never, abort.signal)) {
        const reply = r as unknown as { lines: string[]; exit?: number | null };
        if (reply.lines.length) this.output.update((v) => [...v, ...reply.lines]);
        if (reply.exit !== null && reply.exit !== undefined) this.exit.set(reply.exit);
      }
    } catch (e) {
      if (!abort.signal.aborted) {
        this.problem.set(e instanceof CallFailed ? e.message : 'The tool could not run.');
      }
    } finally {
      this.running.set(false);
    }
  }

  protected stop(): void {
    this.abort?.abort();
    this.running.set(false);
  }
}
