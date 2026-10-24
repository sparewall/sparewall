import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { TestBed } from '@angular/core/testing';

import { ApiClient, CallFailed, jsonSeq } from './api-client';

async function* chunks(...parts: string[]) {
  yield* parts;
}

async function collect(it: AsyncIterable<unknown>) {
  const out: unknown[] = [];
  for await (const v of it) out.push(v);
  return out;
}

describe('jsonSeq', () => {
  it('splits records on RS, whatever the chunks', async () => {
    const got = await collect(
      jsonSeq(chunks('\x1e{"event":{"ty', 'pe":"subscribed"}}\n\x1e{"a"', ':1}\n')),
    );
    expect(got).toEqual([{ event: { type: 'subscribed' } }, { a: 1 }]);
  });

  it('yields a record as soon as its LF arrives', async () => {
    let more!: () => void;
    const later = new Promise<void>((r) => (more = r));
    async function* quiet() {
      yield '\x1e{"event":{"type":"subscribed"}}\n';
      await later;
      yield '\x1e{"b":2}\n';
    }
    const records = jsonSeq(quiet());
    expect((await records.next()).value).toEqual({ event: { type: 'subscribed' } });
    const next = records.next();
    more();
    expect((await next).value).toEqual({ b: 2 });
  });

  it('takes a last record without a trailing RS', async () => {
    expect(await collect(jsonSeq(chunks('\x1e{"a":1}\n\x1e{"b":2}')))).toEqual([
      { a: 1 },
      { b: 2 },
    ]);
  });
});

describe('ApiClient', () => {
  let api: ApiClient;
  let http: HttpTestingController;

  beforeEach(() => {
    TestBed.configureTestingModule({
      providers: [provideHttpClient(), provideHttpClientTesting()],
    });
    api = TestBed.inject(ApiClient);
    http = TestBed.inject(HttpTestingController);
  });

  afterEach(() => http.verify());

  it('posts the parameters to /call/<method>', async () => {
    const reply = api.call('org.sparewall.Firewall.History', { limit: 5 });
    const req = http.expectOne('/call/org.sparewall.Firewall.History');
    expect(req.request.method).toBe('POST');
    expect(req.request.body).toEqual({ limit: 5 });
    req.flush({ generations: [] });
    expect(await reply).toEqual({ generations: [] });
  });

  it("turns an error reply into CallFailed with the node's message", async () => {
    const reply = api.call('org.sparewall.Auth.ListUsers', {});
    http.expectOne('/call/org.sparewall.Auth.ListUsers').flush(
      {
        error: 'org.sparewall.Firewall.PermissionDenied',
        parameters: { role: 'viewer', reason: 'admin only' },
        message: 'permission denied: admin only',
      },
      { status: 403, statusText: 'Forbidden' },
    );
    const e = await reply.then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(e).toBeInstanceOf(CallFailed);
    expect((e as CallFailed).status).toBe(403);
    expect((e as CallFailed).error).toBe('org.sparewall.Firewall.PermissionDenied');
    expect((e as CallFailed).message).toBe('permission denied: admin only');
  });
});
