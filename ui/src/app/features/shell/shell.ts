import { BreakpointObserver } from '@angular/cdk/layout';
import { Component, OnDestroy, OnInit, computed, inject, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatListModule } from '@angular/material/list';
import { MatMenuModule } from '@angular/material/menu';
import { MatSnackBar } from '@angular/material/snack-bar';
import { MatSidenavModule } from '@angular/material/sidenav';
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatTooltipModule } from '@angular/material/tooltip';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';
import { map } from 'rxjs';

import { CallFailed } from '../../api/api-client';
import { NodeEvents } from '../../core/node-events';
import { NodeStatus } from '../../core/node-status';
import { PendingChange } from '../../core/pending-change';
import { Role, Session } from '../../core/session';
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
    MatTooltipModule,
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

  protected readonly node = inject(NodeStatus);
  /** The navigation as icons only, leaving room for a page's own (the editor's sections). */
  protected readonly rail = signal(remembered() === 'rail');
  /** A phone's width: the navigation is a drawer over the page, closed until asked for. */
  protected readonly narrow = toSignal(
    inject(BreakpointObserver)
      .observe(NARROW)
      .pipe(map((r) => r.matches)),
    { initialValue: false },
  );
  protected readonly drawer = signal(false);

  private readonly allPages = [
    { path: '/status', icon: 'monitor_heart', label: 'Status', role: 'viewer' as Role },
    { path: '/policy', icon: 'grid_view', label: 'Zone policy', role: 'viewer' as Role },
    { path: '/config', icon: 'tune', label: 'Configuration', role: 'viewer' as Role },
    { path: '/history', icon: 'history', label: 'History', role: 'viewer' as Role },
    { path: '/users', icon: 'group', label: 'Users', role: 'admin' as Role, admin: true },
    { path: '/tokens', icon: 'key', label: 'API tokens', role: 'admin' as Role, admin: true },
  ];
  /** The pages the user's role can use: the firewall's, then administration's. */
  protected readonly groups = computed(() => {
    this.session.role();
    const pages = this.allPages.filter((p) => this.session.can(p.role));
    return [
      { label: 'Firewall', pages: pages.filter((p) => !p.admin) },
      { label: 'Administration', pages: pages.filter((p) => p.admin) },
    ].filter((g) => g.pages.length);
  });

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

  protected toggleNav(): void {
    if (this.narrow()) {
      this.drawer.update((d) => !d);
      return;
    }
    this.rail.update((r) => !r);
    remember(this.rail() ? 'rail' : 'full');
  }

  protected signOut(): void {
    void this.session.signOut();
  }
}

const NARROW = '(max-width: 599.98px)';

/** This browser's choice of navigation; storage may be unavailable (a private window). */
const NAV_KEY = 'sparewall.nav';

function remembered(): string | null {
  try {
    return localStorage.getItem(NAV_KEY);
  } catch {
    return null;
  }
}

function remember(v: string): void {
  try {
    localStorage.setItem(NAV_KEY, v);
  } catch {
    // Not remembered, then.
  }
}
