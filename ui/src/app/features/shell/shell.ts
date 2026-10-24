import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatListModule } from '@angular/material/list';
import { MatMenuModule } from '@angular/material/menu';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatSidenavModule } from '@angular/material/sidenav';
import { MatToolbarModule } from '@angular/material/toolbar';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

import { CallFailed } from '../../api/api-client';
import { NodeEvents } from '../../core/node-events';
import { PendingChange } from '../../core/pending-change';
import { Session } from '../../core/session';
import { countdown } from '../../shared/countdown';

/** The frame around every page once signed in: navigation and the user's menu. */
@Component({
  selector: 'app-shell',
  imports: [
    MatButtonModule,
    MatIconModule,
    MatListModule,
    MatMenuModule,
    MatSidenavModule,
    MatToolbarModule,
    RouterLink,
    RouterLinkActive,
    RouterOutlet,
  ],
  templateUrl: './shell.html',
  styleUrl: './shell.scss',
})
export class Shell implements OnInit, OnDestroy {
  protected readonly session = inject(Session);
  protected readonly events = inject(NodeEvents);
  protected readonly pending = inject(PendingChange);
  private readonly snack = inject(MatSnackBar);
  protected readonly countdown = countdown;

  protected readonly pages = [
    { path: '/status', icon: 'monitor_heart', label: 'Status' },
    { path: '/config', icon: 'tune', label: 'Configuration' },
    { path: '/history', icon: 'history', label: 'History' },
  ];

  ngOnInit(): void {
    this.events.start();
  }

  ngOnDestroy(): void {
    this.events.stop();
  }

  protected async keep(): Promise<void> {
    await this.act(() => this.pending.confirm(), 'Confirmed.');
  }

  protected async revert(): Promise<void> {
    await this.act(() => this.pending.revert(), 'Reverted.');
  }

  private async act(f: () => Promise<void>, done: string): Promise<void> {
    try {
      await f();
      this.snack.open(done, undefined, { duration: 4000 });
    } catch (e) {
      this.snack.open(e instanceof CallFailed ? e.message : 'That failed.', 'Close');
    }
  }

  protected signOut(): void {
    void this.session.signOut();
  }
}
