import { httpResource } from '@angular/common/http';
import { Component, computed, inject } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatDialog } from '@angular/material/dialog';
import { MatIconModule } from '@angular/material/icon';
import { MatTableModule } from '@angular/material/table';

import { callUrl } from '../../api/api-client';
import { Reply } from '../../api/api.model';
import { Session } from '../../core/session';
import { VpnConfig, VpnConfigData } from './vpn-config';

export interface VpnPeerRow {
  instance: string;
  peer: string;
  addresses: string;
  site: boolean;
  ports: number[];
}

/** The document's VPN peers, by instance, for the table. */
export function peerRows(vpn: Record<string, unknown> | null | undefined): VpnPeerRow[] {
  const rows: VpnPeerRow[] = [];
  for (const [instance, v] of Object.entries(vpn ?? {})) {
    const inst = v as {
      listen_port: number;
      extra_ports?: number[];
      peers?: Record<string, { addresses?: string[]; endpoint?: string | null }>;
    };
    const ports = [inst.listen_port, ...(inst.extra_ports ?? [])];
    for (const [peer, p] of Object.entries(inst.peers ?? {})) {
      rows.push({
        instance,
        peer,
        addresses: (p.addresses ?? []).join(', '),
        site: !!p.endpoint,
        ports,
      });
    }
  }
  return rows;
}

/** VPN peers (#310), and for admins each peer's configuration. */
@Component({
  selector: 'app-vpn',
  imports: [MatButtonModule, MatIconModule, MatTableModule],
  template: `
    <header class="page-header">
      <h1>VPN</h1>
      <span class="subtitle">Remote-access and site-to-site peers</span>
    </header>
    @if (config.error()) {
      <p class="problem" role="alert">The configuration could not be read.</p>
    }
    @if (config.hasValue()) {
      @if (!rows().length) {
        <p>No VPN peers: add them under the configuration's VPN section.</p>
      } @else {
        <div class="panel">
          <table mat-table [dataSource]="rows()">
            <ng-container matColumnDef="instance">
              <th mat-header-cell *matHeaderCellDef>Instance</th>
              <td mat-cell *matCellDef="let r">{{ r.instance }}</td>
            </ng-container>
            <ng-container matColumnDef="peer">
              <th mat-header-cell *matHeaderCellDef>Peer</th>
              <td mat-cell *matCellDef="let r">{{ r.peer }}</td>
            </ng-container>
            <ng-container matColumnDef="kind">
              <th mat-header-cell *matHeaderCellDef>Kind</th>
              <td mat-cell *matCellDef="let r">{{ r.site ? 'Site-to-site' : 'Remote access' }}</td>
            </ng-container>
            <ng-container matColumnDef="addresses">
              <th mat-header-cell *matHeaderCellDef>Addresses</th>
              <td mat-cell *matCellDef="let r">{{ r.addresses }}</td>
            </ng-container>
            <ng-container matColumnDef="actions">
              <th mat-header-cell *matHeaderCellDef>
                <span class="cdk-visually-hidden">Actions</span>
              </th>
              <td mat-cell *matCellDef="let r">
                @if (session.can('admin')) {
                  <button matButton (click)="open(r)">
                    <mat-icon>qr_code</mat-icon>
                    Configuration
                  </button>
                }
              </td>
            </ng-container>
            <tr mat-header-row *matHeaderRowDef="columns"></tr>
            <tr mat-row *matRowDef="let row; columns: columns"></tr>
          </table>
        </div>
      }
    }
  `,
  styles: `
    table {
      width: 100%;
    }
    .problem {
      color: var(--mat-sys-error);
    }
  `,
})
export class Vpn {
  private readonly dialog = inject(MatDialog);
  protected readonly session = inject(Session);
  protected readonly config = httpResource<Reply<'org.sparewall.Firewall.GetConfig'>>(() => ({
    url: callUrl('org.sparewall.Firewall.GetConfig'),
    method: 'POST',
    body: {},
  }));
  protected readonly rows = computed(() =>
    this.config.hasValue()
      ? peerRows(this.config.value().config.vpn as Record<string, unknown> | undefined)
      : [],
  );
  protected readonly columns = ['instance', 'peer', 'kind', 'addresses', 'actions'];

  protected open(r: VpnPeerRow): void {
    this.dialog.open<VpnConfig, VpnConfigData>(VpnConfig, {
      data: { instance: r.instance, peer: r.peer, ports: r.ports, site: r.site },
      width: '520px',
    });
  }
}
