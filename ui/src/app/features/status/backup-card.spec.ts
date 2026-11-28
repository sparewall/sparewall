import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';

import { ApiClient } from '../../api/api-client';
import { Session } from '../../core/session';
import { BackupCard } from './backup-card';

describe('BackupCard (#311)', () => {
  async function render(
    backup: unknown,
    check: unknown,
    role = 'admin',
    call: (m: string, p: unknown) => Promise<unknown> = async () => ({}),
  ) {
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(),
        provideHttpClientTesting(),
        provideRouter([]),
        { provide: ApiClient, useValue: { call } },
        { provide: Session, useValue: { can: (w: string) => w === 'viewer' || role === 'admin' } },
      ],
    });
    const fixture = TestBed.createComponent(BackupCard);
    fixture.componentRef.setInput('check', check);
    TestBed.tick();
    TestBed.inject(HttpTestingController)
      .expectOne('/call/org.sparewall.Firewall.GetConfig')
      .flush({ config: { schema: 8, backup }, generation: { id: 3 } });
    await fixture.whenStable();
    fixture.detectChanges();
    return { fixture, el: fixture.nativeElement as HTMLElement };
  }

  const ok = { name: 'backup', level: 'ok', message: 'last backup 2026-11-27T03:00:00Z' };

  it('shows the schedule, the repository and the last run', async () => {
    const { el } = await render(
      { enabled: true, repository: 's3:s3.example/fw', schedule: 'daily' },
      ok,
    );
    expect(el.textContent).toContain('Scheduled: daily');
    expect(el.textContent).toContain('s3:s3.example/fw');
    expect(el.textContent).toContain('The last backup 2026-11-27T03:00:00Z.');
    expect(el.querySelector('a')).toBeNull();
  });

  it('links a failed run to the backup unit’s logs', async () => {
    const { el } = await render(
      { enabled: true },
      {
        name: 'backup',
        level: 'degraded',
        message: 'the last backup failed: repository unreachable',
      },
    );
    expect(el.textContent).toContain('the last backup failed: repository unreachable');
    expect(el.textContent).toContain('Kept on the node only');
    const a = el.querySelector('a')!;
    expect(a.getAttribute('href')).toBe('/logs?unit=sparewall-backup.service');
  });

  it('backs up now for an admin, and shows the reply', async () => {
    const calls: unknown[] = [];
    const { el, fixture } = await render({ enabled: false }, undefined, 'admin', async (m, p) => {
      calls.push([m, p]);
      return {
        path: '/var/lib/sparewall/backups/b.tar',
        digest: 'sha256:ab',
        snapshot: '1a2b',
        secrets: ['s3'],
      };
    });
    expect(el.textContent).toContain('No scheduled backups');
    el.querySelector('button')!.click();
    await fixture.whenStable();
    fixture.detectChanges();
    expect(calls).toEqual([['org.sparewall.Firewall.Backup', {}]]);
    expect(el.textContent).toContain('/var/lib/sparewall/backups/b.tar');
    expect(el.textContent).toContain('1a2b');
    expect(el.textContent).toContain('s3');
  });

  it('offers no backup to a viewer', async () => {
    const { el } = await render({ enabled: true }, ok, 'viewer');
    expect(el.querySelector('button')).toBeNull();
  });
});
