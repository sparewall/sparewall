import { HttpErrorResponse, httpResource } from '@angular/common/http';
import { Component, DestroyRef, computed, inject, linkedSignal, signal } from '@angular/core';
import { MatButtonToggleModule } from '@angular/material/button-toggle';
import { MatCardModule } from '@angular/material/card';
import { MatIconModule } from '@angular/material/icon';

import { callUrl } from '../../api/api-client';
import { Reply } from '../../api/api.model';
import { SLOTS, Series, TimeChart } from '../../shared/time-chart';

/** A window of history, and the step that keeps it to ~150 points. */
interface Window {
  key: string;
  label: string;
  seconds: number;
  step: number;
}

export const WINDOWS: Window[] = [
  { key: '1h', label: '1 h', seconds: 3600, step: 30 },
  { key: '24h', label: '24 h', seconds: 86400, step: 600 },
  { key: '7d', label: '7 d', seconds: 7 * 86400, step: 3600 },
];

/** One chart: its query (given the rate window), and how to read it. */
interface Spec {
  id: string;
  title: string;
  query: (rate: string) => string;
  name: (labels: Record<string, string>) => string;
  format: (v: number) => string;
  max?: number;
  /** Shown only when it has data. */
  optional?: boolean;
}

const SI = ['', 'k', 'M', 'G', 'T'];

/** `1.5 M` and the like, for rates. */
export function si(v: number, unit: string): string {
  let i = 0;
  while (Math.abs(v) >= 1000 && i < SI.length - 1) {
    v /= 1000;
    i++;
  }
  const n = v >= 100 || v === 0 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2);
  return `${n.includes('.') ? n.replace(/\.?0+$/, '') : n} ${SI[i]}${unit}`;
}

const percent = (v: number) => `${Math.round(v * 100)}%`;

export const SPECS: Spec[] = [
  {
    id: 'in',
    title: 'Traffic in',
    query: (r) => `sum by (device) (rate(node_network_receive_bytes_total[${r}])) * 8`,
    name: (l) => l['device'] ?? '?',
    format: (v) => si(v, 'bit/s'),
  },
  {
    id: 'out',
    title: 'Traffic out',
    query: (r) => `sum by (device) (rate(node_network_transmit_bytes_total[${r}])) * 8`,
    name: (l) => l['device'] ?? '?',
    format: (v) => si(v, 'bit/s'),
  },
  {
    id: 'load',
    title: 'CPU and memory',
    query: (r) =>
      `label_replace(1 - avg(rate(node_cpu_seconds_total{mode="idle"}[${r}])), "series", "CPU", "", "")` +
      ` or label_replace(1 - sum(node_memory_MemAvailable_bytes) / sum(node_memory_MemTotal_bytes),` +
      ` "series", "Memory", "", "")`,
    name: (l) => l['series'] ?? '?',
    format: percent,
    max: 1,
  },
  {
    id: 'conntrack',
    title: 'Connection tracking',
    query: () => `sum(sparewall_conntrack_entries) / sum(sparewall_conntrack_max)`,
    name: () => 'Table use',
    format: percent,
    max: 1,
  },
  {
    id: 'rules',
    title: 'Rule hits',
    query: (r) => `sum by (rule) (rate(sparewall_rule_packets_total{rule=~"rule:.+"}[${r}]))`,
    // rule:wan->lan:https as "wan->lan: https".
    name: (l) => (l['rule'] ?? '?').replace(/^rule:(.*):([^:]*)$/, '$1: $2'),
    format: (v) => si(v, 'pkt/s'),
    optional: true,
  },
];

interface Matrix {
  metric: Record<string, string>;
  values: [number, string][];
}

/**
 * A range query's matrix as series. More than the chart's slots keeps the
 * busiest, by their sum, and folds the rest into "Other"; the kept ones go
 * by name, so a series keeps its colour when the window changes.
 */
export function toSeries(result: unknown, name: (l: Record<string, string>) => string): Series[] {
  const rows = Array.isArray(result) ? (result as Matrix[]) : [];
  const all: Series[] = rows.map((m) => ({
    name: name(m.metric ?? {}),
    points: (m.values ?? []).map(([t, v]) => [Number(t), Number(v)] as [number, number]),
  }));
  const total = (s: Series) => s.points.reduce((a, [, v]) => a + (Number.isFinite(v) ? v : 0), 0);
  const byName = (a: Series, b: Series) => a.name.localeCompare(b.name);
  if (all.length <= SLOTS) return all.sort(byName);
  const ranked = [...all].sort((a, b) => total(b) - total(a));
  const kept = ranked.slice(0, SLOTS - 1).sort(byName);
  const sums = new Map<number, number>();
  for (const s of ranked.slice(SLOTS - 1))
    for (const [t, v] of s.points) sums.set(t, (sums.get(t) ?? 0) + v);
  const other: Series = {
    name: 'Other',
    points: [...sums.entries()].sort((a, b) => a[0] - b[0]),
  };
  return [...kept, other];
}

/** Whether a call failed because the node keeps no history. */
export function noHistory(e: unknown): boolean {
  return (
    e instanceof HttpErrorResponse &&
    e.status === 400 &&
    (e.error as { error?: string } | null)?.error === 'org.sparewall.Firewall.NotSupported'
  );
}

/** The node's history (`metrics.mode: local`), as charts over a window. */
@Component({
  selector: 'app-metrics-history',
  imports: [MatButtonToggleModule, MatCardModule, MatIconModule, TimeChart],
  template: `
    <mat-card appearance="outlined" class="history" data-testid="history">
      <mat-card-header>
        <mat-icon matCardAvatar>monitoring</mat-icon>
        <mat-card-title>History</mat-card-title>
        @if (!unavailable()) {
          <mat-button-toggle-group
            class="window"
            aria-label="Window"
            hideSingleSelectionIndicator
            [value]="window().key"
            (change)="pick($event.value)"
          >
            @for (w of windows; track w.key) {
              <mat-button-toggle [value]="w.key">{{ w.label }}</mat-button-toggle>
            }
          </mat-button-toggle-group>
        }
      </mat-card-header>
      <mat-card-content>
        @if (unavailable()) {
          <p data-testid="no-history">
            This node keeps no history: charts need <code>metrics.mode: local</code>.
            <a [href]="docs" target="_blank" rel="noopener">How history works</a>
          </p>
        } @else {
          <div class="charts">
            @for (c of charts; track c.spec.id) {
              @if (!c.spec.optional || c.series().length) {
                <section
                  [class.loading]="c.res.isLoading()"
                  [attr.data-testid]="'chart-' + c.spec.id"
                >
                  <h3>{{ c.spec.title }}</h3>
                  @if (c.failed(); as f) {
                    <p class="problem" role="alert">{{ f }}</p>
                  } @else {
                    <app-time-chart
                      [series]="c.series()"
                      [start]="range().start"
                      [end]="range().end"
                      [step]="range().step"
                      [format]="c.spec.format"
                      [max]="c.spec.max"
                      [label]="c.spec.title + ', ' + window().label"
                    />
                  }
                </section>
              }
            }
          </div>
        }
      </mat-card-content>
    </mat-card>
  `,
  styles: `
    mat-card-header {
      align-items: center;
    }
    .window {
      margin-left: auto;
    }
    .charts {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(min(100%, 360px), 1fr));
      gap: 24px;
      margin-top: 8px;
    }
    section {
      min-width: 0;
      transition: opacity 0.2s;

      &.loading {
        opacity: 0.6;
      }
    }
    h3 {
      font: var(--mat-sys-title-small);
      margin: 0 0 8px;
    }
    .problem {
      color: var(--mat-sys-error);
    }
  `,
})
export class MetricsHistory {
  protected readonly windows = WINDOWS;
  protected readonly docs =
    'https://github.com/sparewall/sparewall/blob/main/docs/operations.md#history-a-local-prometheus';

  protected readonly window = signal(WINDOWS[0]);
  /** Bumped every minute, to move the window along. */
  private readonly tick = signal(0);

  protected readonly range = computed(() => {
    this.tick();
    const w = this.window();
    const end = Math.floor(Date.now() / 1000 / w.step) * w.step;
    return { start: end - w.seconds, end, step: w.step };
  });

  protected readonly charts = SPECS.map((spec) => {
    const res = httpResource<Reply<'org.sparewall.Metrics.QueryRange'>>(() => {
      const r = this.range();
      return {
        url: callUrl('org.sparewall.Metrics.QueryRange'),
        method: 'POST',
        body: {
          query: spec.query(`${Math.max(r.step, 60)}s`),
          start: String(r.start),
          end: String(r.end),
          step: String(r.step),
        },
      };
    });
    // The last chart drawn stays while the next one loads.
    const series = linkedSignal<Series[] | undefined, Series[]>({
      source: () => (res.hasValue() ? toSeries(res.value().result, spec.name) : undefined),
      computation: (now, prev) => now ?? prev?.value ?? [],
    });
    const failed = computed(() => {
      const e = res.error();
      if (!e || noHistory(e)) return null;
      const msg =
        e instanceof HttpErrorResponse
          ? (e.error as { message?: string } | null)?.message
          : undefined;
      return msg ?? 'The history could not be read.';
    });
    return { spec, res, series, failed };
  });

  protected readonly unavailable = computed(() =>
    this.charts.some((c) => noHistory(c.res.error())),
  );

  constructor() {
    const id = setInterval(() => this.tick.update((n) => n + 1), 60_000);
    inject(DestroyRef).onDestroy(() => clearInterval(id));
  }

  protected pick(key: string) {
    const w = WINDOWS.find((x) => x.key === key);
    if (w) this.window.set(w);
  }
}
