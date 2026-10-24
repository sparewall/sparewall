import { HttpClient, provideHttpClient, withInterceptors } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';
import { firstValueFrom } from 'rxjs';

import { requestHeader } from './request-header';
import { Session } from './session';

describe('requestHeader', () => {
  const ended = vi.fn();
  let http: HttpClient;
  let backend: HttpTestingController;

  beforeEach(() => {
    ended.mockReset();
    TestBed.configureTestingModule({
      providers: [
        provideHttpClient(withInterceptors([requestHeader])),
        provideHttpClientTesting(),
        { provide: Session, useValue: { ended } },
      ],
    });
    http = TestBed.inject(HttpClient);
    backend = TestBed.inject(HttpTestingController);
  });

  it('marks API calls with the custom header', () => {
    void firstValueFrom(http.post('/call/org.sparewall.Firewall.Status', {}));
    const req = backend.expectOne('/call/org.sparewall.Firewall.Status');
    expect(req.request.headers.get('X-Sparewall-Request')).toBe('1');
    req.flush({});
  });

  it('leaves other requests alone', () => {
    void firstValueFrom(http.get('/openapi.json'));
    const req = backend.expectOne('/openapi.json');
    expect(req.request.headers.has('X-Sparewall-Request')).toBe(false);
    req.flush({});
  });

  it('ends the session when the node no longer takes it', async () => {
    const r = firstValueFrom(http.post('/call/org.sparewall.Firewall.Status', {})).catch(() => 0);
    backend
      .expectOne('/call/org.sparewall.Firewall.Status')
      .flush({}, { status: 401, statusText: '' });
    await r;
    expect(ended).toHaveBeenCalled();
  });

  it('does not treat a failed login as an ended session', async () => {
    const r = firstValueFrom(http.post('/call/org.sparewall.Auth.Login', {})).catch(() => 0);
    backend.expectOne('/call/org.sparewall.Auth.Login').flush({}, { status: 401, statusText: '' });
    await r;
    expect(ended).not.toHaveBeenCalled();
  });
});
