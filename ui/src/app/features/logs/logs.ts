import { DatePipe } from '@angular/common';
import { Component, DestroyRef, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatSelectModule } from '@angular/material/select';
import { MatSlideToggleModule } from '@angular/material/slide-toggle';
import { ActivatedRoute } from '@angular/router';

import { ApiClient, CallFailed } from '../../api/api-client';
import { NodeSwitch } from '../../shared/node-switch';
import { Schemas } from '../../api/api.model';

export type LogEntry = Schemas['org.sparewall.Diagnostics.LogEntry'];

export const PRIORITIES = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'];

/** How far back, as journalctl reads `--since`. */
export const SINCE = [
  { value: '-15m', label: 'Last 15 minutes' },
  { value: '-1h', label: 'Last hour' },
  { value: '-24h', label: 'Last day' },
  { value: '-7d', label: 'Last week' },
  { value: '', label: 'Everything kept' },
];

/** Entries a follow keeps on the page; older ones drop off the end. */
export const KEEP = 2000;

/** A priority's name, and how it reads: problem, warning or plain. */
export function priority(p: number): { name: string; level: string } {
  const name = PRIORITIES[p] ?? 'info';
  return { name, level: p <= 3 ? 'problem' : p === 4 ? 'warning' : '' };
}

/** `sparewall-kea.service` as `kea`, `sparewalld.service` as `sparewalld`. */
export function shortUnit(u: string): string {
  return u.replace(/\.service$/, '').replace(/^sparewall-(?=.)/, '');
}

/** The journal of Sparewall's own units, read-only (#261). */
@Component({
  selector: 'app-logs',
  imports: [
    DatePipe,
    FormsModule,
    MatButtonModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatSelectModule,
    MatSlideToggleModule,
    NodeSwitch,
  ],
  template: `
    <div class="page-header">
      <h1>Logs</h1>
      <span class="subtitle">Sparewall's units on this node, newest first</span>
      <app-node-switch [node]="node()" (nodeChange)="node.set($event); load()" />
    </div>
    <form class="filters" (ngSubmit)="load()">
      <mat-form-field subscriptSizing="dynamic">
        <mat-label>Units</mat-label>
        <mat-select multiple [(ngModel)]="units" name="units" (selectionChange)="load()">
          @for (u of known(); track u) {
            <mat-option [value]="u">{{ shortUnit(u) }}</mat-option>
          }
        </mat-select>
      </mat-form-field>
      <mat-form-field subscriptSizing="dynamic">
        <mat-label>Priority</mat-label>
        <mat-select [(ngModel)]="priorityFilter" name="priority" (selectionChange)="load()">
          <mat-option [value]="''">Any</mat-option>
          @for (p of priorities; track p) {
            <mat-option [value]="p">{{ p }} and worse</mat-option>
          }
        </mat-select>
      </mat-form-field>
      <mat-form-field subscriptSizing="dynamic">
        <mat-label>Since</mat-label>
        <mat-select [(ngModel)]="since" name="since" (selectionChange)="load()">
          @for (s of sinces; track s.value) {
            <mat-option [value]="s.value">{{ s.label }}</mat-option>
          }
        </mat-select>
      </mat-form-field>
      <mat-form-field subscriptSizing="dynamic" class="grow">
        <mat-label>Text</mat-label>
        <input matInput [(ngModel)]="grep" name="grep" maxlength="256" />
        <button matIconSuffix mat-icon-button type="submit" aria-label="Search">
          <mat-icon>search</mat-icon>
        </button>
      </mat-form-field>
      <mat-slide-toggle [checked]="following()" (change)="setFollow($event.checked)">
        Follow
      </mat-slide-toggle>
    </form>
    @if (problem(); as p) {
      <p class="problem" role="alert">{{ p }}</p>
    }
    <ol class="entries" [class.loading]="loading()" aria-live="polite" data-testid="entries">
      @for (e of entries(); track e.usec + e.unit + e.message) {
        <li [class]="priority(e.priority).level">
          <button
            type="button"
            class="line"
            [attr.aria-expanded]="open() === e"
            (click)="open.set(open() === e ? null : e)"
          >
            <time [attr.datetime]="e.time">{{ e.time | date: 'MMM d HH:mm:ss' }}</time>
            <span class="unit">{{ shortUnit(e.unit) }}</span>
            <span class="prio">{{ priority(e.priority).name }}</span>
            <span class="msg">{{ e.message }}</span>
          </button>
          @if (open() === e) {
            <dl class="fields">
              @if (e.identifier) {
                <dt>Program</dt>
                <dd>{{ e.identifier }}</dd>
              }
              <dt>Time</dt>
              <dd>{{ e.time }}</dd>
              @for (f of fields(e); track f[0]) {
                <dt>{{ f[0] }}</dt>
                <dd>{{ f[1] }}</dd>
              }
            </dl>
          }
        </li>
      } @empty {
        @if (!loading()) {
          <li class="none">No entries.</li>
        }
      }
    </ol>
    @if (older() !== null && !following()) {
      <button mat-stroked-button type="button" (click)="more()" [disabled]="loading()">
        Older
      </button>
    }
  `,
  styles: `
    .filters {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px 12px;
      margin-bottom: 16px;

      mat-form-field {
        width: 180px;
      }
      .grow {
        flex: 1 1 220px;
      }
    }
    .entries {
      list-style: none;
      margin: 0 0 16px;
      padding: 0;
      font: var(--mat-sys-body-small);
      transition: opacity 0.2s;

      &.loading {
        opacity: 0.6;
      }
    }
    li {
      border-bottom: 1px solid var(--mat-sys-outline-variant);
    }
    .line {
      display: grid;
      grid-template-columns: 9.5em 8em 4.5em 1fr;
      gap: 8px;
      width: 100%;
      padding: 4px 8px;
      border: 0;
      background: none;
      color: inherit;
      font: inherit;
      text-align: left;
      cursor: pointer;

      &:hover {
        background: var(--mat-sys-surface-container-low);
      }
    }
    time,
    .prio {
      font-variant-numeric: tabular-nums;
      color: var(--mat-sys-on-surface-variant);
    }
    .unit {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .msg {
      white-space: pre-wrap;
      overflow-wrap: anywhere;
    }
    .problem .prio,
    .problem .msg {
      color: var(--mat-sys-error);
    }
    .warning .prio {
      color: var(--sw-degraded);
    }
    .fields {
      display: grid;
      grid-template-columns: max-content 1fr;
      gap: 2px 12px;
      margin: 0;
      padding: 4px 8px 8px 9.5em;

      dt {
        color: var(--mat-sys-on-surface-variant);
      }
      dd {
        margin: 0;
        white-space: pre-wrap;
        overflow-wrap: anywhere;
      }
    }
    .none {
      padding: 16px 8px;
      color: var(--mat-sys-on-surface-variant);
    }
    p.problem {
      color: var(--mat-sys-error);
    }
    @media (max-width: 720px) {
      .line {
        grid-template-columns: 7em 1fr;
      }
      .prio {
        display: none;
      }
      .msg {
        grid-column: 1 / -1;
      }
      .fields {
        padding-left: 8px;
      }
    }
  `,
})
export class Logs implements OnInit {
  private readonly api = inject(ApiClient);

  protected readonly priorities = PRIORITIES;
  protected readonly sinces = SINCE;
  protected readonly priority = priority;
  protected readonly shortUnit = shortUnit;

  protected units: string[] = [];
  protected priorityFilter = '';
  protected since = '-1h';
  protected grep = '';

  /** The pair's other node, when reading it through this one (#268). */
  protected readonly node = signal<string | null>(null);
  protected readonly known = signal<string[]>([]);
  protected readonly entries = signal<LogEntry[]>([]);
  protected readonly older = signal<string | null>(null);
  protected readonly loading = signal(false);
  protected readonly problem = signal<string | null>(null);
  protected readonly following = signal(false);
  protected readonly open = signal<LogEntry | null>(null);
  private abort: AbortController | null = null;

  constructor() {
    inject(DestroyRef).onDestroy(() => this.abort?.abort());
  }

  /** A link may name a unit (`/logs?unit=sparewall-backup.service`), as a failed backup's does (#311). */
  private readonly route = inject(ActivatedRoute, { optional: true });

  ngOnInit(): void {
    const unit = this.route?.snapshot.queryParamMap.get('unit');
    if (unit) this.units = [unit];
    void this.load();
  }

  protected fields(e: LogEntry): [string, string][] {
    return Object.entries(e.fields);
  }

  private params(before?: string) {
    return {
      units: this.units.length ? this.units : null,
      priority: this.priorityFilter || null,
      since: this.since || null,
      grep: this.grep.trim() || null,
      limit: 200,
      before: before ?? null,
      node: this.node(),
    };
  }

  /** The newest entries for the filters, afresh. */
  async load(): Promise<void> {
    this.loading.set(true);
    this.problem.set(null);
    try {
      const r = await this.api.call('org.sparewall.Diagnostics.Logs', this.params());
      this.known.set(r.units);
      this.entries.set(r.entries);
      this.older.set(r.older ?? null);
    } catch (e) {
      this.problem.set(e instanceof CallFailed ? e.message : 'The logs could not be read.');
    } finally {
      this.loading.set(false);
    }
    if (this.following()) this.follow();
  }

  /** The page before the oldest shown. */
  async more(): Promise<void> {
    const before = this.older();
    if (before === null) return;
    this.loading.set(true);
    try {
      const r = await this.api.call('org.sparewall.Diagnostics.Logs', this.params(before));
      this.entries.update((v) => [...v, ...r.entries]);
      this.older.set(r.older ?? null);
    } catch (e) {
      this.problem.set(e instanceof CallFailed ? e.message : 'The logs could not be read.');
    } finally {
      this.loading.set(false);
    }
  }

  protected setFollow(on: boolean): void {
    this.following.set(on);
    if (on) this.follow();
    else this.abort?.abort();
  }

  /** New entries at the top as they are logged, until switched off. */
  private follow(): void {
    this.abort?.abort();
    const abort = new AbortController();
    this.abort = abort;
    const p = this.params();
    void (async () => {
      try {
        for await (const r of this.api.stream(
          'org.sparewall.Diagnostics.FollowLogs',
          { units: p.units, priority: p.priority, grep: p.grep, node: p.node },
          abort.signal,
        )) {
          const e = r.entry;
          if (e) this.entries.update((v) => [e, ...v].slice(0, KEEP));
        }
      } catch (e) {
        if (!abort.signal.aborted) {
          this.problem.set(e instanceof CallFailed ? e.message : 'Following the logs stopped.');
          this.following.set(false);
        }
      }
    })();
  }
}
