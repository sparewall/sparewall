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
import { Schemas } from '../../api/api.model';
import { NodeSwitch } from '../../shared/node-switch';
import { KEEP, SINCE } from '../logs/logs';

export type RuleHit = Schemas['org.sparewall.Diagnostics.RuleHit'];

/** Hits of logged rules, policy defaults and forwards (#262). */
@Component({
  selector: 'app-hits',
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
      <h1>Logged traffic</h1>
      <span class="subtitle">Hits of rules with logging on, newest first</span>
      <app-node-switch [node]="node()" (nodeChange)="node.set($event); load()" />
    </div>
    <form class="filters" (ngSubmit)="load()">
      <mat-form-field subscriptSizing="dynamic">
        <mat-label>Rule</mat-label>
        <input matInput [(ngModel)]="rule" name="rule" placeholder="users->self:ssh" />
      </mat-form-field>
      <mat-form-field subscriptSizing="dynamic">
        <mat-label>Zone pair</mat-label>
        <input matInput [(ngModel)]="pair" name="pair" placeholder="wan->lan" />
      </mat-form-field>
      <mat-form-field subscriptSizing="dynamic">
        <mat-label>Address or prefix</mat-label>
        <input matInput [(ngModel)]="address" name="address" />
      </mat-form-field>
      <mat-form-field subscriptSizing="dynamic" class="port">
        <mat-label>Port</mat-label>
        <input matInput type="number" min="0" max="65535" [(ngModel)]="port" name="port" />
      </mat-form-field>
      <mat-form-field subscriptSizing="dynamic">
        <mat-label>Since</mat-label>
        <mat-select [(ngModel)]="since" name="since" (selectionChange)="load()">
          @for (s of sinces; track s.value) {
            <mat-option [value]="s.value">{{ s.label }}</mat-option>
          }
        </mat-select>
      </mat-form-field>
      <button mat-stroked-button type="submit">
        <mat-icon>search</mat-icon>
        Show
      </button>
      <mat-slide-toggle [checked]="following()" (change)="setFollow($event.checked)">
        Follow
      </mat-slide-toggle>
    </form>
    @if (problem(); as p) {
      <p class="problem" role="alert">{{ p }}</p>
    }
    <div class="table" [class.loading]="loading()">
      <table data-testid="hits">
        <thead>
          <tr>
            <th scope="col">Time</th>
            <th scope="col">Rule</th>
            <th scope="col">Packet</th>
          </tr>
        </thead>
        <tbody>
          @for (h of hits(); track h.usec + h.rule + h.packet) {
            <tr>
              <td class="time">
                <time [attr.datetime]="h.time">{{ h.time | date: 'MMM d HH:mm:ss' }}</time>
              </td>
              <td>
                <button type="button" class="rule" (click)="only(h.rule)">{{ h.rule }}</button>
              </td>
              <td class="packet">{{ h.packet }}</td>
            </tr>
          } @empty {
            @if (!loading()) {
              <tr>
                <td colspan="3" class="none">No hits.</td>
              </tr>
            }
          }
        </tbody>
      </table>
    </div>
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
      .port {
        width: 100px;
      }
    }
    .table {
      overflow-x: auto;
      margin-bottom: 16px;
      transition: opacity 0.2s;

      &.loading {
        opacity: 0.6;
      }
    }
    table {
      width: 100%;
      border-collapse: collapse;
      font: var(--mat-sys-body-small);
    }
    th {
      text-align: left;
      font-weight: 500;
      color: var(--mat-sys-on-surface-variant);
    }
    th,
    td {
      padding: 4px 8px;
      border-bottom: 1px solid var(--mat-sys-outline-variant);
      vertical-align: top;
    }
    .time {
      white-space: nowrap;
      font-variant-numeric: tabular-nums;
      color: var(--mat-sys-on-surface-variant);
    }
    .packet {
      font-family: monospace;
      overflow-wrap: anywhere;
    }
    .rule {
      padding: 0;
      border: 0;
      background: none;
      color: var(--mat-sys-primary);
      font: inherit;
      cursor: pointer;
      white-space: nowrap;
    }
    .none {
      padding: 16px 8px;
      color: var(--mat-sys-on-surface-variant);
    }
    p.problem {
      color: var(--mat-sys-error);
    }
  `,
})
export class Hits implements OnInit {
  private readonly api = inject(ApiClient);
  private readonly route = inject(ActivatedRoute);

  protected readonly sinces = SINCE;

  protected rule = '';
  protected pair = '';
  protected address = '';
  protected port: number | null = null;
  protected since = '-1h';

  /** The pair's other node, when reading it through this one (#268). */
  protected readonly node = signal<string | null>(null);
  protected readonly hits = signal<RuleHit[]>([]);
  protected readonly older = signal<string | null>(null);
  protected readonly loading = signal(false);
  protected readonly problem = signal<string | null>(null);
  protected readonly following = signal(false);
  private abort: AbortController | null = null;

  constructor() {
    inject(DestroyRef).onDestroy(() => this.abort?.abort());
  }

  ngOnInit(): void {
    // A link from a rule: /hits?rule=users->self:ssh, or ?pair=wan->lan.
    const q = this.route.snapshot.queryParamMap;
    this.rule = q.get('rule') ?? '';
    this.pair = q.get('pair') ?? '';
    void this.load();
  }

  private filters() {
    return {
      rule: this.rule.trim() || null,
      pair: this.pair.trim() || null,
      address: this.address.trim() || null,
      port: this.port ?? null,
      node: this.node(),
    };
  }

  /** The newest hits for the filters, afresh. */
  async load(): Promise<void> {
    this.loading.set(true);
    this.problem.set(null);
    try {
      const r = await this.api.call('org.sparewall.Diagnostics.Hits', {
        ...this.filters(),
        since: this.since || null,
        limit: 200,
      });
      this.hits.set(r.hits);
      this.older.set(r.older ?? null);
    } catch (e) {
      this.problem.set(e instanceof CallFailed ? e.message : 'The hits could not be read.');
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
      const r = await this.api.call('org.sparewall.Diagnostics.Hits', {
        ...this.filters(),
        since: this.since || null,
        limit: 200,
        before,
      });
      this.hits.update((v) => [...v, ...r.hits]);
      this.older.set(r.older ?? null);
    } catch (e) {
      this.problem.set(e instanceof CallFailed ? e.message : 'The hits could not be read.');
    } finally {
      this.loading.set(false);
    }
  }

  /** Only this rule's hits. */
  protected only(rule: string): void {
    this.rule = rule;
    this.pair = '';
    void this.load();
  }

  protected setFollow(on: boolean): void {
    this.following.set(on);
    if (on) this.follow();
    else this.abort?.abort();
  }

  private follow(): void {
    this.abort?.abort();
    const abort = new AbortController();
    this.abort = abort;
    void (async () => {
      try {
        for await (const r of this.api.stream(
          'org.sparewall.Diagnostics.FollowHits',
          this.filters(),
          abort.signal,
        )) {
          const h = r.hit;
          if (h) this.hits.update((v) => [h, ...v].slice(0, KEEP));
        }
      } catch (e) {
        if (!abort.signal.aborted) {
          this.problem.set(e instanceof CallFailed ? e.message : 'Following the hits stopped.');
          this.following.set(false);
        }
      }
    })();
  }
}
