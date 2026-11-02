import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { MatDialog } from '@angular/material/dialog';
import { Subject, of } from 'rxjs';

import { NodeEvent, NodeEvents } from '../../core/node-events';
import { Session } from '../../core/session';
import { UpgradePanel } from './upgrade-panel';

function setup(role = 'admin', answer: unknown = true) {
  const events$ = new Subject<NodeEvent>();
  const connected = signal(true);
  TestBed.configureTestingModule({
    providers: [
      provideHttpClient(),
      provideHttpClientTesting(),
      { provide: NodeEvents, useValue: { events$, connected } },
      { provide: Session, useValue: { can: (w: string) => w !== 'admin' || role === 'admin' } },
      { provide: MatDialog, useValue: { open: () => ({ afterClosed: () => of(answer) }) } },
    ],
  });
  const fixture = TestBed.createComponent(UpgradePanel);
  fixture.componentRef.setInput('node', 'fw1');
  fixture.detectChanges();
  const http = TestBed.inject(HttpTestingController);
  const el = fixture.nativeElement as HTMLElement;
  const text = () => {
    fixture.detectChanges();
    return el.textContent ?? '';
  };
  // The click, then the confirmation's answer: the call goes out a turn later.
  const click = async () => {
    el.querySelector('button')!.click();
    await new Promise((r) => setTimeout(r));
  };
  const upgrade = (step: string, detail = '') => events$.next({ type: 'upgrade', step, detail });
  return { fixture, http, el, text, click, events$, connected, upgrade };
}

describe('UpgradePanel', () => {
  it('offers admins the button, and tells others an admin can upgrade', () => {
    expect(setup().el.querySelector('button')?.textContent).toContain('Upgrade');
    TestBed.resetTestingModule();
    const other = setup('operator');
    expect(other.el.querySelector('button')).toBeNull();
    expect(other.text()).toContain('An admin can upgrade from here.');
  });

  it('starts nothing when the confirmation is declined', async () => {
    const t = setup('admin', null);
    await t.click();
    t.http.expectNone('/call/org.sparewall.Upgrade.Start');
  });

  it('follows a standalone node through its reboot and reconnects', async () => {
    const t = setup();
    await t.click();
    t.http.expectOne('/call/org.sparewall.Upgrade.Start').flush({ plan: ['stage', 'reboot'] });
    await new Promise((r) => setTimeout(r));
    expect(t.text()).toContain('Upgrading…');
    t.upgrade('stage', 'staging reg/sw:stable on this node');
    t.upgrade('reboot', 'rebooting into the new image');
    expect(t.text()).toContain('rebooting into the new image');
    t.connected.set(false);
    expect(t.text()).toContain('fw1 is rebooting into the new image.');
    t.connected.set(true);
    t.fixture.detectChanges();
    t.http.expectOne('/call/org.sparewall.Firewall.Status').flush({
      node: 'fw1',
      update: { running: '0.4.1' },
      health: { level: 'ok' },
      sync: { peer: null },
    });
    await new Promise((r) => setTimeout(r));
    expect(t.text()).toContain('fw1 is back, running 0.4.1: health ok.');
  });

  it('shows the step that failed, and in a pair how to finish', async () => {
    const t = setup();
    t.fixture.componentRef.setInput('paired', true);
    await t.click();
    t.http.expectOne('/call/org.sparewall.Upgrade.Start').flush({ plan: [] });
    await new Promise((r) => setTimeout(r));
    t.upgrade('failed', 'fw2 did not come back healthy');
    expect(t.text()).toContain('The upgrade stopped: fw2 did not come back healthy');
    expect(t.text()).toContain('If a run stops halfway');
  });

  it('calls a dropped connection an error unless this node reboots', async () => {
    const t = setup();
    await t.click();
    t.http.expectOne('/call/org.sparewall.Upgrade.Start').flush({ plan: [] });
    await new Promise((r) => setTimeout(r));
    t.upgrade('download', 'downloading');
    t.connected.set(false);
    expect(t.text()).toContain('The connection to fw1 was lost during the upgrade.');
  });

  it('disables the button while another run is going', () => {
    const t = setup();
    t.upgrade('stage-peer', 'fw2: staging x on fw1');
    t.fixture.detectChanges();
    expect(t.el.querySelector('button')?.disabled).toBe(true);
    t.upgrade('done', 'finished');
    t.fixture.detectChanges();
    expect(t.el.querySelector('button')?.disabled).toBe(false);
  });

  it('shows why the node refused to start', async () => {
    const t = setup();
    await t.click();
    t.http
      .expectOne('/call/org.sparewall.Upgrade.Start')
      .flush(
        { error: 'org.sparewall.Firewall.ApplyFailed', message: 'older than this node' },
        { status: 400, statusText: 'Bad Request' },
      );
    await new Promise((r) => setTimeout(r));
    expect(t.text()).toContain('older than this node');
  });
});
