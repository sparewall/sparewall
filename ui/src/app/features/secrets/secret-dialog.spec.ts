import { TestBed } from '@angular/core/testing';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';

import { SecretData, SecretDialog } from './secret-dialog';

describe('SecretDialog', () => {
  const close = vi.fn();

  async function fill(data: SecretData, values: string[]) {
    close.mockReset();
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [SecretDialog],
      providers: [
        { provide: MAT_DIALOG_DATA, useValue: data },
        { provide: MatDialogRef, useValue: { close } },
      ],
    });
    const fixture = TestBed.createComponent(SecretDialog);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const inputs = [...el.querySelectorAll('input:not([type=checkbox])')] as HTMLInputElement[];
    values.forEach((v, i) => {
      inputs[i].value = v;
      inputs[i].dispatchEvent(new Event('input'));
    });
    await fixture.whenStable();
    el.querySelector('form')!.dispatchEvent(new Event('submit'));
    await fixture.whenStable();
    return el;
  }

  it('adds a secret, the pair’s by default', async () => {
    await fill({ pair: true }, [' cf-token ', 'v@lue', 'v@lue']);
    expect(close).toHaveBeenCalledWith({ name: 'cf-token', value: 'v@lue', cluster: true });
  });

  it('wants the value twice the same, and a name the node takes', async () => {
    let el = await fill({ pair: false }, ['cf', 'one', 'two']);
    expect(close).not.toHaveBeenCalled();
    expect(el.textContent).toContain('The values differ.');
    el = await fill({ pair: false }, ['-bad', 'one', 'one']);
    expect(close).not.toHaveBeenCalled();
    expect(el.textContent).toContain('starting with a letter or digit');
  });

  it('replaces a named secret without asking its name, and says the version goes up', async () => {
    const el = await fill({ name: 'backup-password', pair: false }, ['new', 'new']);
    expect(el.textContent).toContain('Replace backup-password');
    expect(close).toHaveBeenCalledWith({ name: 'backup-password', value: 'new', cluster: true });
  });

  it('never puts a value in the page', async () => {
    const el = await fill({ pair: false }, ['cf', 'hunter2', 'hunter2']);
    expect(el.textContent).not.toContain('hunter2');
    for (const i of el.querySelectorAll('input:not([type=checkbox])')) {
      if ((i as HTMLInputElement).value === 'hunter2')
        expect((i as HTMLInputElement).type).toBe('password');
    }
  });
});
