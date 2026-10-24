import { TestBed } from '@angular/core/testing';
import { MAT_DIALOG_DATA, MatDialogRef } from '@angular/material/dialog';

import { NameDialog } from './name-dialog';

describe('NameDialog', () => {
  const close = vi.fn();

  async function open(name: string, typed: string) {
    close.mockReset();
    TestBed.configureTestingModule({
      imports: [NameDialog],
      providers: [
        { provide: MAT_DIALOG_DATA, useValue: { title: 'Add', name, taken: ['users', 'wan'] } },
        { provide: MatDialogRef, useValue: { close } },
      ],
    });
    const fixture = TestBed.createComponent(NameDialog);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const input = el.querySelector('input')!;
    input.value = typed;
    input.dispatchEvent(new Event('input'));
    await fixture.whenStable();
    el.querySelector('form')!.dispatchEvent(new Event('submit'));
    await fixture.whenStable();
    return el;
  }

  it('closes with a new name, trimmed', async () => {
    await open('', ' iot ');
    expect(close).toHaveBeenCalledWith('iot');
  });

  it('refuses a name that is taken, and says so', async () => {
    const el = await open('', 'users');
    expect(close).not.toHaveBeenCalled();
    expect(el.textContent).toContain('users already exists.');
  });

  it('lets a rename keep its own name', async () => {
    await open('users', 'users');
    expect(close).toHaveBeenCalledWith('users');
  });
});
