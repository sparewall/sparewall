import { TestBed } from '@angular/core/testing';
import { MatDialog } from '@angular/material/dialog';
import { of } from 'rxjs';

import { ApiClient } from '../../api/api-client';
import { SyncState } from '../../api/status.model';
import { Session } from '../../core/session';
import { PairCard, failoverBlocked } from './pair-card';

const sync = (over: Partial<SyncState> = {}): SyncState => ({
  active: 7,
  confirmed: 7,
  pending: null,
  desired_hash: 'h',
  applied_hash: 'h',
  state: 'in-sync',
  peer: 'fw2',
  peer_reachable: true,
  peer_active: 7,
  last_error: null,
  ...over,
});

describe('failoverBlocked', () => {
  it('says why the node would refuse, as failover.rs does', () => {
    expect(failoverBlocked('MASTER', sync())).toBeNull();
    expect(failoverBlocked('BACKUP', sync())).toContain('Only the master');
    expect(failoverBlocked('MASTER', sync({ peer_reachable: false }))).toContain(
      "fw2 can't be reached",
    );
    expect(failoverBlocked('MASTER', sync({ state: 'diverged' }))).toContain(
      "isn't in sync (diverged)",
    );
    expect(failoverBlocked('MASTER', sync({ peer: null }))).toContain('no peer');
  });
});

describe('PairCard (#313)', () => {
  async function render(y: SyncState | undefined, role = 'MASTER', who = 'operator') {
    const calls: unknown[] = [];
    let asked = '';
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [
        {
          provide: ApiClient,
          useValue: {
            call: async (m: string, p: unknown) => {
              calls.push([m, p]);
              return m.endsWith('Failover')
                ? { master: 'fw2', message: 'fw2 holds the gateway addresses' }
                : { generation: { id: 9 } };
            },
          },
        },
        {
          provide: MatDialog,
          useValue: {
            open: (_c: unknown, o: { data: { text: string } }) => {
              asked = o.data.text;
              return { afterClosed: () => of(true) };
            },
          },
        },
        {
          provide: Session,
          useValue: {
            can: (w: string) => w === 'viewer' || (w === 'operator' && who !== 'viewer'),
          },
        },
      ],
    });
    const fixture = TestBed.createComponent(PairCard);
    fixture.componentRef.setInput('sync', y);
    fixture.componentRef.setInput('node', 'fw1');
    fixture.componentRef.setInput('role', role);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const button = (text: string) =>
      [...el.querySelectorAll('button')].find((b) => b.textContent?.includes(text)) as
        HTMLButtonElement | undefined;
    const click = async (text: string) => {
      button(text)!.click();
      await fixture.whenStable();
      fixture.detectChanges();
    };
    return { el, calls, button, click, asked: () => asked };
  }

  it('shows nothing on a standalone node', async () => {
    const { el } = await render(sync({ peer: null }));
    expect(el.querySelector('[data-testid=pair]')).toBeNull();
  });

  it('lets an operator hand the gateway to the peer, and says what happened', async () => {
    const { el, calls, button, click, asked } = await render(sync());
    expect(button('Hand the gateway to fw2')!.disabled).toBe(false);
    await click('Hand the gateway to fw2');
    expect(asked()).toContain('fw2 takes the gateway addresses');
    expect(calls).toEqual([['org.sparewall.Cluster.Failover', { to: 'fw2' }]]);
    expect(el.textContent).toContain('fw2 holds the gateway addresses');
  });

  it('disables failover, saying why, where the node would refuse it', async () => {
    const { el, button } = await render(sync(), 'BACKUP');
    expect(button('Hand the gateway')!.disabled).toBe(true);
    expect(el.textContent).toContain('Only the master hands the gateway over');
  });

  it('offers sync only to a diverged pair, either way, and runs it', async () => {
    let r = await render(sync());
    expect(r.button("Take fw2's")).toBeUndefined();
    r = await render(sync({ state: 'diverged', peer_active: 6 }));
    expect(r.button("Keep this node's (generation 7)")).toBeDefined();
    await r.click("Take fw2's (generation 6)");
    expect(r.asked()).toContain(
      "fw1 runs fw2's configuration (generation 6) in place of its own (generation 7)",
    );
    expect(r.calls).toEqual([['org.sparewall.Firewall.Sync', { from_node: 'fw2' }]]);
    expect(r.el.textContent).toContain("Both nodes run fw2's configuration: generation 9 here.");
  });

  it('offers a viewer neither', async () => {
    const { el } = await render(sync({ state: 'diverged' }), 'MASTER', 'viewer');
    expect(el.querySelector('[data-testid=pair]')).not.toBeNull();
    expect(el.querySelectorAll('button').length).toBe(0);
  });
});
