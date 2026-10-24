import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';

import { ApiClient } from '../api/api-client';
import { NeedsViewer, Session } from './session';

describe('Session', () => {
  const calls: string[] = [];
  const api = {
    call: async (method: string) => {
      calls.push(method);
      if (method.endsWith('Login')) {
        return { user: 'alice', role: 'operator', expires: Date.now() / 1000 + 3600, token: '' };
      }
      return {};
    },
  };
  const navigate = vi.fn().mockResolvedValue(true);

  beforeEach(() => {
    localStorage.clear();
    calls.length = 0;
    TestBed.configureTestingModule({
      providers: [
        { provide: ApiClient, useValue: api },
        { provide: Router, useValue: { navigate } },
      ],
    });
  });

  it('knows the role after signing in, and what it allows', async () => {
    const s = TestBed.inject(Session);
    expect(s.user()).toBeUndefined();
    expect(s.can('viewer')).toBe(false);
    await s.signIn('alice', 'secret');
    expect(s.user()).toBe('alice');
    expect(s.can('viewer')).toBe(true);
    expect(s.can('operator')).toBe(true);
    expect(s.can('admin')).toBe(false);
  });

  it('remembers the user across a reload until the session expires', async () => {
    await TestBed.inject(Session).signIn('alice', 'secret');
    const stored = JSON.parse(localStorage.getItem('sparewall.session')!);
    expect(stored).not.toHaveProperty('token');
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [
        { provide: ApiClient, useValue: api },
        { provide: Router, useValue: { navigate } },
      ],
    });
    expect(TestBed.inject(Session).user()).toBe('alice');
    localStorage.setItem('sparewall.session', JSON.stringify({ ...stored, expires: 1 }));
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [
        { provide: ApiClient, useValue: api },
        { provide: Router, useValue: { navigate } },
      ],
    });
    expect(TestBed.inject(Session).user()).toBeUndefined();
  });

  it('turns away monitor users, ending the session their login opened', async () => {
    const monitor = {
      call: async (method: string) => {
        calls.push(method);
        return method.endsWith('Login')
          ? { user: 'prom', role: 'monitor', expires: Date.now() / 1000 + 3600, token: '' }
          : {};
      },
    };
    TestBed.overrideProvider(ApiClient, { useValue: monitor });
    const s = TestBed.inject(Session);
    await expect(s.signIn('prom', 'secret')).rejects.toBeInstanceOf(NeedsViewer);
    expect(calls).toContain('org.sparewall.Auth.Logout');
    expect(s.user()).toBeUndefined();
  });

  it('forgets the user and goes to sign in when signing out', async () => {
    const s = TestBed.inject(Session);
    await s.signIn('alice', 'secret');
    await s.signOut();
    expect(calls).toContain('org.sparewall.Auth.Logout');
    expect(s.user()).toBeUndefined();
    expect(localStorage.getItem('sparewall.session')).toBeNull();
    expect(navigate).toHaveBeenCalledWith(['/login']);
  });
});
