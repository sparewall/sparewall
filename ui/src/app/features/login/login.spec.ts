import { TestBed } from '@angular/core/testing';
import { Router } from '@angular/router';

import { CallFailed } from '../../api/api-client';
import { Session } from '../../core/session';
import { Login } from './login';

describe('Login', () => {
  const signIn = vi.fn();
  const navigate = vi.fn().mockResolvedValue(true);

  beforeEach(() => {
    signIn.mockReset();
    navigate.mockClear();
    TestBed.configureTestingModule({
      imports: [Login],
      providers: [
        { provide: Session, useValue: { signIn } },
        { provide: Router, useValue: { navigate } },
      ],
    });
  });

  async function fill(user: string, password: string) {
    const fixture = TestBed.createComponent(Login);
    await fixture.whenStable();
    const el = fixture.nativeElement as HTMLElement;
    const [u, p] = Array.from(el.querySelectorAll('input'));
    u.value = user;
    u.dispatchEvent(new Event('input'));
    p.value = password;
    p.dispatchEvent(new Event('input'));
    el.querySelector('form')!.dispatchEvent(new Event('submit'));
    await fixture.whenStable();
    await new Promise((r) => setTimeout(r));
    await fixture.whenStable();
    return el;
  }

  it('signs in and goes to the status page', async () => {
    signIn.mockResolvedValue(undefined);
    await fill('alice', 'secret');
    expect(signIn).toHaveBeenCalledWith('alice', 'secret');
    expect(navigate).toHaveBeenCalledWith(['/']);
  });

  it('says so when the password is wrong', async () => {
    signIn.mockRejectedValue(new CallFailed(401));
    const el = await fill('alice', 'nope');
    expect(el.querySelector('[role=alert]')?.textContent).toContain('wrong');
    expect(navigate).not.toHaveBeenCalled();
  });

  it('asks for both fields before calling the node', async () => {
    const el = await fill('', '');
    expect(signIn).not.toHaveBeenCalled();
    expect(el.textContent).toContain('Enter your user name.');
  });
});
