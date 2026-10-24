import { Service, computed, inject, signal } from '@angular/core';
import { Router } from '@angular/router';

import { ApiClient } from '../api/api-client';

export type Role = 'monitor' | 'viewer' | 'operator' | 'admin';

const RANK: Record<Role, number> = { monitor: 0, viewer: 1, operator: 2, admin: 3 };

interface SignedIn {
  user: string;
  role: Role;
  /** Unix time the session ends. */
  expires: number;
}

/**
 * Who is signed in, for the page's own use: what to show and offer. The
 * session itself is an HttpOnly cookie the page never sees, and the node
 * checks every call against its role.
 */
const KEY = 'sparewall.session';

function load(): SignedIn | undefined {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) ?? 'null') as SignedIn | null;
    return v && v.expires * 1000 > Date.now() ? v : undefined;
  } catch {
    return undefined;
  }
}

function save(v: SignedIn | undefined) {
  try {
    if (v) localStorage.setItem(KEY, JSON.stringify(v));
    else localStorage.removeItem(KEY);
  } catch {
    // Without storage, a reload asks to sign in again.
  }
}

@Service()
export class Session {
  private readonly api = inject(ApiClient);
  private readonly router = inject(Router);
  private readonly current = signal(load());

  readonly user = computed(() => this.current()?.user);
  readonly role = computed(() => this.current()?.role);

  /** Whether the signed-in user's role includes `role`. */
  can(role: Role): boolean {
    const mine = this.role();
    return mine !== undefined && RANK[mine] >= RANK[role];
  }

  async signIn(user: string, password: string): Promise<void> {
    const r = await this.api.call('org.sparewall.Auth.Login', { user, password });
    const v: SignedIn = { user: r.user, role: r.role as Role, expires: r.expires };
    save(v);
    this.current.set(v);
  }

  async signOut(): Promise<void> {
    try {
      await this.api.call('org.sparewall.Auth.Logout', {});
    } finally {
      this.ended();
    }
  }

  /** The session is over (signed out, expired or revoked): sign in again. */
  ended(): void {
    save(undefined);
    this.current.set(undefined);
    void this.router.navigate(['/login']);
  }
}
