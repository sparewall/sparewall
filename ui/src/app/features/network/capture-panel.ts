import { Component, DestroyRef, computed, inject, input, signal } from '@angular/core';
import { DecimalPipe } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';

import { ApiClient, CallFailed } from '../../api/api-client';
import { Parameters, Reply } from '../../api/api.model';

type Capture = 'org.sparewall.Diagnostics.Capture';
export type CaptureReply = Reply<Capture>;

/** The size limits offered, in bytes. */
export const SIZES = [
  { label: '1 MiB', bytes: 1 << 20 },
  { label: '8 MiB', bytes: 8 << 20 },
  { label: '32 MiB', bytes: 32 << 20 },
];

const ENDS: Record<string, string> = {
  time: 'it reached its time limit',
  size: 'it reached its size limit',
  stopped: 'tcpdump stopped',
};

/** The bytes of a reply's `data`, which is base64. */
export function decode(data: string): Uint8Array {
  const s = atob(data);
  const b = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
  return b;
}

/**
 * A short packet capture on a network, downloaded as a pcap when it ends
 * (#265). Admin only, as the method is: it holds other people's traffic.
 */
@Component({
  selector: 'app-capture-panel',
  imports: [
    DecimalPipe,
    FormsModule,
    MatButtonModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatSelectModule,
  ],
  template: `
    <p class="note">
      A capture holds other people's traffic: each is recorded in the node's journal, with who
      started it. One runs on a node at a time.
    </p>
    <form class="capture" (ngSubmit)="start()">
      <mat-form-field subscriptSizing="dynamic">
        <mat-label>Network</mat-label>
        <mat-select [(ngModel)]="network" name="network" required>
          @for (n of networks(); track n) {
            <mat-option [value]="n">{{ n }}</mat-option>
          }
        </mat-select>
      </mat-form-field>
      <mat-form-field subscriptSizing="dynamic" class="grow">
        <mat-label>Filter (pcap-filter syntax)</mat-label>
        <input
          matInput
          [(ngModel)]="filter"
          name="filter"
          maxlength="512"
          placeholder="icmp, tcp port 443 and host 192.0.2.10"
        />
      </mat-form-field>
      <mat-form-field subscriptSizing="dynamic" class="small">
        <mat-label>Seconds</mat-label>
        <input matInput type="number" min="1" max="300" [(ngModel)]="seconds" name="seconds" />
      </mat-form-field>
      <mat-form-field subscriptSizing="dynamic" class="small">
        <mat-label>At most</mat-label>
        <mat-select [(ngModel)]="maxSize" name="maxSize">
          @for (s of sizes; track s.bytes) {
            <mat-option [value]="s.bytes">{{ s.label }}</mat-option>
          }
        </mat-select>
      </mat-form-field>
      @if (running()) {
        <button mat-stroked-button type="button" (click)="stop()">Stop</button>
      } @else {
        <button mat-flat-button type="submit" [disabled]="!network">Capture</button>
      }
    </form>
    @if (problem(); as p) {
      <p class="problem" role="alert">{{ p }}</p>
    }
    @if (running() || pcap()) {
      <p class="progress" aria-live="polite" data-testid="progress">
        {{ packets() | number }} packets, {{ bytes() | number }} bytes{{ ended() }}
      </p>
    }
    @if (pcap(); as file) {
      <a mat-stroked-button [href]="file.url" [download]="file.name" data-testid="download">
        <mat-icon>download</mat-icon>
        {{ file.name }}
      </a>
    }
  `,
  styles: `
    .capture {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px 12px;
      margin: 8px 0;

      mat-form-field {
        width: 180px;
      }
      .grow {
        flex: 1 1 260px;
      }
      .small {
        width: 110px;
      }
    }
    .note,
    .progress {
      color: var(--mat-sys-on-surface-variant);
      font: var(--mat-sys-body-medium);
    }
    .problem {
      color: var(--mat-sys-error);
    }
  `,
})
export class CapturePanel {
  private readonly api = inject(ApiClient);

  /** The networks to capture on. */
  readonly networks = input<string[]>([]);
  /** The pair's other node, to capture on through this one (#268). */
  readonly node = input<string | null>(null);

  protected readonly sizes = SIZES;
  protected network = '';
  protected filter = '';
  protected seconds = 30;
  protected maxSize = 8 << 20;

  protected readonly running = signal(false);
  protected readonly problem = signal<string | null>(null);
  protected readonly packets = signal(0);
  protected readonly bytes = signal(0);
  private readonly end = signal<string | null>(null);
  /** The finished capture, as a file to download. */
  protected readonly pcap = signal<{ url: string; name: string } | null>(null);
  protected readonly ended = computed(() => {
    const e = this.end();
    if (e === null) return this.running() ? '…' : ': stopped here';
    return `: ${ENDS[e] ?? e}`;
  });
  private abort: AbortController | null = null;

  constructor() {
    inject(DestroyRef).onDestroy(() => {
      this.abort?.abort();
      this.release();
    });
  }

  /** The call for the form as it is. */
  call(): Parameters<Capture> & { network: string } {
    return {
      network: this.network,
      filter: this.filter.trim() || null,
      seconds: this.seconds || null,
      max_size: this.maxSize,
      node: this.node(),
    };
  }

  async start(): Promise<void> {
    if (!this.network || this.running()) return;
    this.abort?.abort();
    this.release();
    const abort = new AbortController();
    this.abort = abort;
    this.problem.set(null);
    this.packets.set(0);
    this.bytes.set(0);
    this.end.set(null);
    this.running.set(true);
    const parts: Uint8Array[] = [];
    const params = this.call();
    const started = new Date();
    try {
      for await (const reply of this.api.stream(
        'org.sparewall.Diagnostics.Capture',
        params,
        abort.signal,
      )) {
        if (reply.data) parts.push(decode(reply.data));
        this.packets.set(reply.packets);
        this.bytes.set(reply.bytes);
        if (reply.end) this.end.set(reply.end);
      }
    } catch (e) {
      if (!abort.signal.aborted) {
        this.problem.set(e instanceof CallFailed ? e.message : 'The capture could not run.');
      }
    } finally {
      this.running.set(false);
    }
    // Every part ends at a packet's end, so a capture stopped early is
    // still a whole pcap.
    if (parts.length) this.offer(parts, params.node ?? null, params.network, started);
  }

  protected stop(): void {
    this.abort?.abort();
  }

  private offer(parts: Uint8Array[], node: string | null, network: string, at: Date): void {
    const blob = new Blob(parts as BlobPart[], { type: 'application/vnd.tcpdump.pcap' });
    const stamp = at.toISOString().slice(0, 19).replace(/[-:]/g, '').replace('T', '-');
    const where = node ? `${node}-${network}` : network;
    this.pcap.set({ url: URL.createObjectURL(blob), name: `capture-${where}-${stamp}.pcap` });
  }

  private release(): void {
    const p = this.pcap();
    if (p) URL.revokeObjectURL(p.url);
    this.pcap.set(null);
  }
}
