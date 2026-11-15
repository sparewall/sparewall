import { Component, computed, input, signal } from '@angular/core';

/** One line: its name, and its points as `[unix seconds, value]`. */
export interface Series {
  name: string;
  points: [number, number][];
}

/** The most series a chart draws, by its fixed colour slots. */
export const SLOTS = 8;

const W = 600;
const TIME = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit' });
const DAY_TIME = new Intl.DateTimeFormat(undefined, {
  weekday: 'short',
  day: 'numeric',
  month: 'short',
  hour: '2-digit',
  minute: '2-digit',
});
const H = 160;

/**
 * Lines over time, on one axis from zero: hairline gridlines, a legend
 * for two series or more, a crosshair that reads every series at the
 * nearest time (pointer or arrow keys), and the same values as a table.
 */
@Component({
  selector: 'app-time-chart',
  template: `
    <div class="frame" [class.empty]="!series().length">
      <div class="axis-y" aria-hidden="true">
        @for (g of grid(); track g.y) {
          <span [style.top.%]="g.top">{{ format()(g.v) }}</span>
        }
      </div>
      <div
        class="plot"
        tabindex="0"
        role="img"
        [attr.aria-label]="label()"
        (pointermove)="hover($event)"
        (pointerleave)="at.set(null)"
        (blur)="at.set(null)"
        (keydown)="key($event)"
      >
        <svg [attr.viewBox]="'0 0 ' + w + ' ' + h" preserveAspectRatio="none" aria-hidden="true">
          @for (g of grid(); track g.y) {
            <line class="grid" x1="0" [attr.x2]="w" [attr.y1]="g.y" [attr.y2]="g.y" />
          }
          @for (s of drawn(); track s.name; let i = $index) {
            <path [attr.d]="s.d" [style.stroke]="color(i)" />
          }
          @if (cursor(); as c) {
            <line class="cross" [attr.x1]="c.x" [attr.x2]="c.x" y1="0" [attr.y2]="h" />
          }
        </svg>
        @if (!series().length) {
          <p class="none">No data in this window.</p>
        }
        @if (cursor(); as c) {
          <div
            class="tip"
            [class.flip]="c.x > w / 2"
            [style.left.%]="(c.x / w) * 100"
            role="status"
          >
            <div class="when">{{ when(c.t) }}</div>
            @for (r of c.rows; track r.name) {
              <div class="row">
                <span class="key" [style.background]="color(r.slot)"></span>
                <strong>{{ r.value === null ? '–' : format()(r.value) }}</strong>
                <span>{{ r.name }}</span>
              </div>
            }
          </div>
        }
      </div>
      <div class="axis-x" aria-hidden="true">
        <span>{{ when(start()) }}</span>
        <span>{{ when((start() + end()) / 2) }}</span>
        <span>{{ when(end()) }}</span>
      </div>
    </div>
    @if (series().length > 1) {
      <ul class="legend">
        @for (s of series(); track s.name; let i = $index) {
          <li><span class="key" [style.background]="color(i)"></span>{{ s.name }}</li>
        }
      </ul>
    }
    @if (series().length) {
      <details>
        <summary>Table</summary>
        <div class="table">
          <table>
            <thead>
              <tr>
                <th scope="col">Time</th>
                @for (s of series(); track s.name) {
                  <th scope="col">{{ s.name }}</th>
                }
              </tr>
            </thead>
            <tbody>
              @for (t of times(); track t) {
                <tr>
                  <th scope="row">{{ when(t) }}</th>
                  @for (s of series(); track s.name) {
                    <td>{{ valueAt(s, t) }}</td>
                  }
                </tr>
              }
            </tbody>
          </table>
        </div>
      </details>
    }
  `,
  styles: `
    :host {
      display: block;
    }
    .frame {
      display: grid;
      grid-template-columns: auto 1fr;
      grid-template-rows: auto auto;
      column-gap: 8px;
    }
    .axis-y {
      position: relative;
      min-width: 56px;
      font: var(--mat-sys-label-small);
      color: var(--mat-sys-on-surface-variant);
      text-align: right;

      span {
        position: absolute;
        right: 0;
        transform: translateY(-50%);
        white-space: nowrap;
      }
    }
    .plot {
      position: relative;
      height: 160px;
      outline-offset: 2px;
      touch-action: pan-y;

      svg {
        display: block;
        width: 100%;
        height: 100%;
        overflow: visible;
      }
      path {
        fill: none;
        stroke-width: 2px;
        stroke-linejoin: round;
        stroke-linecap: round;
        vector-effect: non-scaling-stroke;
      }
      .grid {
        stroke: var(--mat-sys-outline-variant);
        stroke-width: 1px;
        vector-effect: non-scaling-stroke;
      }
      .cross {
        stroke: var(--mat-sys-on-surface-variant);
        stroke-width: 1px;
        vector-effect: non-scaling-stroke;
      }
    }
    .none {
      position: absolute;
      inset: 0;
      display: grid;
      place-items: center;
      margin: 0;
      color: var(--mat-sys-on-surface-variant);
    }
    .tip {
      position: absolute;
      top: 0;
      margin-left: 12px;
      padding: 6px 8px;
      border-radius: 8px;
      background: var(--mat-sys-inverse-surface);
      color: var(--mat-sys-inverse-on-surface);
      font: var(--mat-sys-body-small);
      pointer-events: none;
      white-space: nowrap;
      z-index: 1;

      &.flip {
        transform: translateX(-100%);
        margin-left: -12px;
      }
      .when {
        opacity: 0.8;
      }
      .row {
        display: flex;
        align-items: center;
        gap: 6px;
      }
    }
    .key {
      display: inline-block;
      width: 12px;
      height: 2px;
      border-radius: 1px;
      flex: none;
    }
    .axis-x {
      grid-column: 2;
      display: flex;
      justify-content: space-between;
      font: var(--mat-sys-label-small);
      color: var(--mat-sys-on-surface-variant);
    }
    .legend {
      display: flex;
      flex-wrap: wrap;
      gap: 4px 16px;
      margin: 8px 0 0;
      padding: 0;
      list-style: none;
      font: var(--mat-sys-body-small);

      li {
        display: flex;
        align-items: center;
        gap: 6px;
      }
    }
    details {
      margin-top: 4px;
      font: var(--mat-sys-body-small);
    }
    summary {
      cursor: pointer;
      color: var(--mat-sys-on-surface-variant);
    }
    .table {
      max-height: 240px;
      overflow: auto;
    }
    table {
      border-collapse: collapse;
      font-variant-numeric: tabular-nums;
    }
    th,
    td {
      padding: 2px 8px;
      text-align: right;
      white-space: nowrap;
    }
    thead th {
      position: sticky;
      top: 0;
      background: var(--mat-sys-surface);
    }
  `,
})
export class TimeChart {
  /** At most {@link SLOTS}, each keeping its slot's colour. */
  readonly series = input.required<Series[]>();
  readonly start = input.required<number>();
  readonly end = input.required<number>();
  /** Seconds between points: a longer gap breaks a line. */
  readonly step = input.required<number>();
  readonly format = input<(v: number) => string>((v) => String(v));
  /** The axis's top, when the values have one (1 for a share). */
  readonly max = input<number | undefined>(undefined);
  readonly label = input('');

  protected readonly w = W;
  protected readonly h = H;
  /** Where the crosshair is, as a fraction of the width. */
  protected readonly at = signal<number | null>(null);

  private readonly top = computed(() => {
    const fixed = this.max();
    if (fixed !== undefined) return fixed;
    let m = 0;
    for (const s of this.series()) for (const [, v] of s.points) if (v > m) m = v;
    return niceCeil(m);
  });

  protected readonly grid = computed(() =>
    [0, 0.5, 1].map((f) => ({ v: this.top() * f, y: H - f * H, top: (1 - f) * 100 })),
  );

  private x(t: number): number {
    const span = this.end() - this.start() || 1;
    return ((t - this.start()) / span) * W;
  }

  private y(v: number): number {
    return H - (Math.max(0, v) / (this.top() || 1)) * H;
  }

  protected readonly drawn = computed(() =>
    this.series().map((s) => {
      let d = '';
      let last: number | undefined;
      for (const [t, v] of s.points) {
        const gap = last === undefined || t - last > this.step() * 1.5;
        d += `${gap ? 'M' : 'L'}${this.x(t).toFixed(1)},${this.y(v).toFixed(1)}`;
        last = t;
      }
      return { name: s.name, d };
    }),
  );

  /** Every time any series has a point at, in order. */
  protected readonly times = computed(() => {
    const all = new Set<number>();
    for (const s of this.series()) for (const [t] of s.points) all.add(t);
    return [...all].sort((a, b) => a - b);
  });

  protected readonly cursor = computed(() => {
    const f = this.at();
    const times = this.times();
    if (f === null || !times.length) return null;
    const want = this.start() + f * (this.end() - this.start());
    let t = times[0];
    for (const c of times) if (Math.abs(c - want) < Math.abs(t - want)) t = c;
    return {
      t,
      x: this.x(t),
      rows: this.series().map((s, slot) => ({
        name: s.name,
        slot,
        value: s.points.find(([pt]) => pt === t)?.[1] ?? null,
      })),
    };
  });

  protected color(slot: number): string {
    return `var(--sw-series-${(slot % SLOTS) + 1})`;
  }

  protected when(t: number): string {
    const long = this.end() - this.start() > 2 * 86400;
    return (long ? DAY_TIME : TIME).format(new Date(t * 1000));
  }

  protected valueAt(s: Series, t: number): string {
    const p = s.points.find(([pt]) => pt === t);
    return p ? this.format()(p[1]) : '–';
  }

  protected hover(e: PointerEvent) {
    const r = (e.currentTarget as HTMLElement).getBoundingClientRect();
    if (r.width > 0) this.at.set(Math.min(1, Math.max(0, (e.clientX - r.left) / r.width)));
  }

  protected key(e: KeyboardEvent) {
    const times = this.times();
    if (!times.length || (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight')) return;
    e.preventDefault();
    const c = this.cursor();
    let i = c ? times.indexOf(c.t) : times.length - 1;
    if (c) i += e.key === 'ArrowLeft' ? -1 : 1;
    i = Math.min(times.length - 1, Math.max(0, i));
    const span = this.end() - this.start() || 1;
    this.at.set((times[i] - this.start()) / span);
  }
}

/** A round number at or above `v`: 1, 2 or 5 times a power of ten. */
export function niceCeil(v: number): number {
  if (v <= 0) return 1;
  const p = 10 ** Math.floor(Math.log10(v));
  for (const m of [1, 2, 5, 10]) if (v <= m * p) return m * p;
  return 10 * p;
}
