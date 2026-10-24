import { Component, OnDestroy, OnInit, inject } from '@angular/core';
import { MatButtonModule } from '@angular/material/button';
import { MatIconModule } from '@angular/material/icon';
import { MatListModule } from '@angular/material/list';
import { MatMenuModule } from '@angular/material/menu';
import { MatSidenavModule } from '@angular/material/sidenav';
import { MatToolbarModule } from '@angular/material/toolbar';
import { RouterLink, RouterLinkActive, RouterOutlet } from '@angular/router';

import { NodeEvents } from '../../core/node-events';
import { Session } from '../../core/session';

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

  protected readonly pages = [
    { path: '/status', icon: 'monitor_heart', label: 'Status' },
    { path: '/history', icon: 'history', label: 'History' },
  ];

  ngOnInit(): void {
    this.events.start();
  }

  ngOnDestroy(): void {
    this.events.stop();
  }

  protected signOut(): void {
    void this.session.signOut();
  }
}
