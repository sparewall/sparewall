import { TestBed } from '@angular/core/testing';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';

import { UserData, UserDialog } from './user-dialog';

describe('UserDialog', () => {
  const close = vi.fn();

  async function fill(data: UserData, values: string[]) {
    close.mockReset();
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      imports: [UserDialog],
      providers: [
        { provide: MAT_DIALOG_DATA, useValue: data },
        { provide: MatDialogRef, useValue: { close } },
      ],
    });
    const fixture = TestBed.createComponent(UserDialog);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const inputs = [...el.querySelectorAll('input')];
    values.forEach((v, i) => {
      inputs[i].value = v;
      inputs[i].dispatchEvent(new Event('input'));
    });
    await fixture.whenStable();
    el.querySelector('form')!.dispatchEvent(new Event('submit'));
    await fixture.whenStable();
    return el;
  }

  const adding: UserData = { taken: ['admin', 'carol'] };

  it('adds a user with a role and a password', async () => {
    await fill(adding, [' dave ', 'long enough', 'long enough']);
    expect(close).toHaveBeenCalledWith({ name: 'dave', role: 'viewer', password: 'long enough' });
  });

  it('holds names to the node rule, and refuses one taken', async () => {
    let el = await fill(adding, ['Dave', 'long enough', 'long enough']);
    expect(close).not.toHaveBeenCalled();
    expect(el.textContent).toContain('starting with a letter');
    el = await fill(adding, ['carol', 'long enough', 'long enough']);
    expect(close).not.toHaveBeenCalled();
    expect(el.textContent).toContain('carol already exists.');
  });

  it('wants the password twice the same, and long enough', async () => {
    let el = await fill(adding, ['dave', 'long enough', 'long enougH']);
    expect(el.textContent).toContain('The passwords differ.');
    el = await fill(adding, ['dave', 'short', 'short']);
    expect(el.textContent).toContain('At least 8 characters.');
    expect(close).not.toHaveBeenCalled();
  });

  it('changes a role without asking for a password', async () => {
    await fill({ name: 'carol', role: 'operator', taken: [] }, []);
    expect(close).toHaveBeenCalledWith({ name: 'carol', role: 'operator', password: '' });
  });
});
