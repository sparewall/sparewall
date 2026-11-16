import { Component, OnInit, inject, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatSelectModule } from '@angular/material/select';
import { MatTabsModule } from '@angular/material/tabs';

import { ApiClient, CallFailed } from '../../api/api-client';
import { Schemas } from '../../api/api.model';
import { Session } from '../../core/session';
import { ToolsPanel } from './tools-panel';

export type Neighbour = Schemas['org.sparewall.Diagnostics.Neighbour'];
export type Route = Schemas['org.sparewall.Diagnostics.Route'];

/** States of a neighbour that mean it does not answer. */
const BAD = ['FAILED', 'INCOMPLETE'];

/** The node's neighbour table and routes, by network (#263). */
@Component({
  selector: 'app-network',
  imports: [
    FormsModule,
    MatButtonModule,
    MatFormFieldModule,
    MatIconModule,
    MatSelectModule,
    MatTabsModule,
    ToolsPanel,
  ],
  template: `
    <div class="page-header">
      <h1>Network</h1>
      <span class="subtitle">What this node sees on its networks, now</span>
    </div>
    <div class="filters">
      <mat-form-field subscriptSizing="dynamic">
        <mat-label>Network</mat-label>
        <mat-select [(ngModel)]="network" (selectionChange)="load()">
          <mat-option [value]="''">All</mat-option>
          @for (n of networks(); track n) {
            <mat-option [value]="n">{{ n }}</mat-option>
          }
        </mat-select>
      </mat-form-field>
      <button mat-stroked-button type="button" (click)="load()" [disabled]="loading()">
        <mat-icon>refresh</mat-icon>
        Refresh
      </button>
    </div>
    @if (problem(); as p) {
      <p class="problem" role="alert">{{ p }}</p>
    }
    <mat-tab-group [class.loading]="loading()">
      <mat-tab label="Neighbours">
        <div class="table">
          <table data-testid="neighbours">
            <thead>
              <tr>
                <th scope="col">Network</th>
                <th scope="col">Interface</th>
                <th scope="col">Address</th>
                <th scope="col">MAC</th>
                <th scope="col">State</th>
              </tr>
            </thead>
            <tbody>
              @for (n of neighbours(); track n.iface + n.address) {
                <tr [class.bad]="isBad(n)">
                  <td>{{ n.network ?? '–' }}</td>
                  <td>{{ n.iface }}</td>
                  <td class="mono">{{ n.address }}</td>
                  <td class="mono">{{ n.mac ?? '–' }}</td>
                  <td>
                    {{ n.state.join(', ') }}
                    @if (n.router) {
                      <span class="tag">router</span>
                    }
                  </td>
                </tr>
              } @empty {
                <tr>
                  <td colspan="5" class="none">No entries.</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
        @if (neighboursCut()) {
          <p class="note">More entries than one reply holds: the rest are left out.</p>
        }
      </mat-tab>
      <mat-tab label="Routes">
        <div class="table">
          <table data-testid="routes">
            <thead>
              <tr>
                <th scope="col">Table</th>
                <th scope="col">Destination</th>
                <th scope="col">Gateway</th>
                <th scope="col">Network</th>
                <th scope="col">Interface</th>
                <th scope="col">Protocol</th>
                <th scope="col">Metric</th>
                <th scope="col">Notes</th>
              </tr>
            </thead>
            <tbody>
              @for (r of routes(); track $index) {
                <tr [class.bad]="r.kind !== 'unicast' || r.flags.includes('linkdown')">
                  <td>{{ r.table }}</td>
                  <td class="mono">
                    {{ r.destination }}
                    @if (r.destination === 'default') {
                      <span class="tag">IPv{{ r.family }}</span>
                    }
                  </td>
                  <td class="mono">{{ r.gateway ?? '–' }}</td>
                  <td>{{ r.network ?? '–' }}</td>
                  <td>{{ r.iface ?? '–' }}</td>
                  <td>{{ r.protocol ?? '–' }}</td>
                  <td>{{ r.metric ?? '–' }}</td>
                  <td>{{ notes(r) }}</td>
                </tr>
              } @empty {
                <tr>
                  <td colspan="8" class="none">No routes.</td>
                </tr>
              }
            </tbody>
          </table>
        </div>
        @if (routesCut()) {
          <p class="note">More routes than one reply holds: the rest are left out.</p>
        }
      </mat-tab>
      @if (session.can('operator')) {
        <mat-tab label="Tools">
          <app-tools-panel [networks]="networks()" />
        </mat-tab>
      }
    </mat-tab-group>
  `,
  styles: `
    .filters {
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 8px 12px;
      margin-bottom: 8px;

      mat-form-field {
        width: 200px;
      }
    }
    mat-tab-group {
      transition: opacity 0.2s;

      &.loading {
        opacity: 0.6;
      }
    }
    .table {
      overflow-x: auto;
      margin: 8px 0 16px;
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
      white-space: nowrap;
    }
    .mono {
      font-family: monospace;
    }
    tr.bad td {
      color: var(--mat-sys-error);
    }
    .tag {
      margin-left: 6px;
      padding: 0 6px;
      border-radius: 8px;
      background: var(--mat-sys-surface-container-high);
      color: var(--mat-sys-on-surface-variant);
    }
    .none,
    .note {
      color: var(--mat-sys-on-surface-variant);
    }
    p.problem {
      color: var(--mat-sys-error);
    }
  `,
})
export class Network implements OnInit {
  private readonly api = inject(ApiClient);
  protected readonly session = inject(Session);

  protected network = '';
  protected readonly neighbours = signal<Neighbour[]>([]);
  protected readonly routes = signal<Route[]>([]);
  protected readonly neighboursCut = signal(false);
  protected readonly routesCut = signal(false);
  protected readonly loading = signal(false);
  protected readonly problem = signal<string | null>(null);
  /** The networks seen so far, for the filter. */
  protected readonly networks = signal<string[]>([]);

  ngOnInit(): void {
    void this.load();
  }

  protected isBad(n: Neighbour): boolean {
    return n.state.some((s) => BAD.includes(s));
  }

  protected notes(r: Route): string {
    const out: string[] = [];
    if (r.kind !== 'unicast') out.push(r.kind);
    out.push(...r.flags);
    if (r.source) out.push(`from ${r.source}`);
    if (r.expires !== null && r.expires !== undefined) out.push(`expires in ${r.expires}s`);
    return out.join(', ');
  }

  async load(): Promise<void> {
    this.loading.set(true);
    this.problem.set(null);
    const network = this.network || null;
    try {
      const [n, r] = await Promise.all([
        this.api.call('org.sparewall.Diagnostics.Neighbours', { network }),
        this.api.call('org.sparewall.Diagnostics.Routes', { network }),
      ]);
      this.neighbours.set(n.neighbours);
      this.routes.set(r.routes);
      this.neighboursCut.set(n.cut);
      this.routesCut.set(r.cut);
      const names = new Set(this.networks());
      for (const x of [...n.neighbours, ...r.routes]) if (x.network) names.add(x.network);
      this.networks.set([...names].sort());
    } catch (e) {
      this.problem.set(e instanceof CallFailed ? e.message : 'The node could not be read.');
    } finally {
      this.loading.set(false);
    }
  }
}
