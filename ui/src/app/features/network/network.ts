import { Component, OnInit, computed, inject, input, signal } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { MatButtonModule } from '@angular/material/button';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatSelectModule } from '@angular/material/select';

import { ApiClient, CallFailed } from '../../api/api-client';
import { Schemas } from '../../api/api.model';
import { Role, Session } from '../../core/session';
import { NodeSwitch } from '../../shared/node-switch';
import { NavGroup, SectionLayout } from '../../shared/section-layout';
import { CapturePanel } from './capture-panel';
import { ToolsPanel } from './tools-panel';

export type Neighbour = Schemas['org.sparewall.Diagnostics.Neighbour'];
export type Route = Schemas['org.sparewall.Diagnostics.Route'];

/** States of a neighbour that mean it does not answer. */
const BAD = ['FAILED', 'INCOMPLETE'];

/** The page's sections, and the role each needs beyond viewer. */
const SECTIONS: { key: string; label: string; role?: Role }[] = [
  { key: 'neighbours', label: 'Neighbours' },
  { key: 'routes', label: 'Routes' },
  { key: 'tools', label: 'Tools', role: 'operator' },
  { key: 'capture', label: 'Capture', role: 'admin' },
];

/**
 * The node's neighbour table and routes, by network (#263), with the
 * diagnostic tools and packet capture, one section each
 * (`/network/<section>`, #304).
 */
@Component({
  selector: 'app-network',
  imports: [
    FormsModule,
    MatButtonModule,
    MatFormFieldModule,
    MatIconModule,
    MatSelectModule,
    CapturePanel,
    NodeSwitch,
    SectionLayout,
    ToolsPanel,
  ],
  template: `
    <div class="page-header">
      <h1>Network</h1>
      <span class="subtitle">What this node sees on its networks, now</span>
      <app-node-switch [node]="node()" (nodeChange)="node.set($event); load()" />
    </div>
    <app-section-layout
      navLabel="Network sections"
      base="/network"
      [groups]="groups()"
      [active]="shown().key"
    >
      @if (shown().key === 'neighbours' || shown().key === 'routes') {
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
      }
      @if (problem(); as p) {
        <p class="problem" role="alert">{{ p }}</p>
      }
      <div class="tables" [class.loading]="loading()">
        @switch (shown().key) {
          @case ('neighbours') {
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
          }
          @case ('routes') {
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
          }
          @case ('tools') {
            @if (shown().disabled) {
              <p class="none" data-testid="needs-role">Tools needs the operator role.</p>
            } @else {
              <app-tools-panel [networks]="networks()" [node]="node()" />
            }
          }
          @case ('capture') {
            @if (shown().disabled) {
              <p class="none" data-testid="needs-role">Capture needs the admin role.</p>
            } @else {
              <app-capture-panel [networks]="networks()" [node]="node()" />
            }
          }
        }
      </div>
    </app-section-layout>
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
    .tables {
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

  /** The section shown, from the route. */
  readonly section = input<string>();

  /** Every section, for every role: those a role can't use are disabled and say which it needs. */
  protected readonly groups = computed((): NavGroup[] => {
    return [
      {
        sections: SECTIONS.map(({ key, label, role }) =>
          role && !this.session.can(role)
            ? { key, label, disabled: true, hint: role }
            : { key, label },
        ),
      },
    ];
  });
  /** The section shown: the route's, or the first one. */
  protected readonly shown = computed(() => {
    const all = this.groups()[0].sections;
    return all.find((s) => s.key === this.section()) ?? all[0];
  });

  protected network = '';
  /** The pair's other node, when reading it through this one (#268). */
  protected readonly node = signal<string | null>(null);
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
        this.api.call('org.sparewall.Diagnostics.Neighbours', { network, node: this.node() }),
        this.api.call('org.sparewall.Diagnostics.Routes', { network, node: this.node() }),
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
