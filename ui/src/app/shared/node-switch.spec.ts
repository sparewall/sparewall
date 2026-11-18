import { signal } from '@angular/core';
import { TestBed } from '@angular/core/testing';
import { provideNoopAnimations } from '@angular/platform-browser/animations';

import { NodeStatus } from '../core/node-status';
import { NodeSwitch } from './node-switch';

async function render(peer: string | null) {
  TestBed.configureTestingModule({
    providers: [
      provideNoopAnimations(),
      { provide: NodeStatus, useValue: { node: signal('fw1'), peer: signal(peer) } },
    ],
  });
  const fixture = TestBed.createComponent(NodeSwitch);
  const picked: (string | null)[] = [];
  fixture.componentInstance.nodeChange.subscribe((n) => picked.push(n));
  fixture.detectChanges();
  await fixture.whenStable();
  return { fixture, el: fixture.nativeElement as HTMLElement, picked };
}

const button = (el: HTMLElement, id: string) =>
  el.querySelector(`[data-testid="${id}"] button`) as HTMLButtonElement;

describe('NodeSwitch', () => {
  it('is not there on a standalone node', async () => {
    const { el } = await render(null);
    expect(el.querySelector('mat-button-toggle-group')).toBeNull();
  });

  it('offers this node and its peer, and says which is picked (null: this one)', async () => {
    const { el, picked, fixture } = await render('fw2');
    expect(button(el, 'this-node').textContent?.trim()).toBe('fw1');
    expect(button(el, 'peer-node').textContent?.trim()).toBe('fw2');
    button(el, 'peer-node').click();
    fixture.componentRef.setInput('node', 'fw2');
    fixture.detectChanges();
    button(el, 'this-node').click();
    expect(picked).toEqual(['fw2', null]);
  });
});
