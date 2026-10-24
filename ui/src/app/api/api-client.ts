import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Service, inject } from '@angular/core';
import { firstValueFrom } from 'rxjs';

import { ApiError, Method, Parameters, Reply, StreamingMethod } from './api.model';

/**
 * The header every call carries. A cross-site form cannot send it, so the
 * gateway takes a session cookie only with it.
 */
export const REQUEST_HEADER = 'X-Sparewall-Request';

export const callUrl = (method: Method) => `/call/${method}`;

/** A call the node refused, or that did not reach it (status 0). */
export class CallFailed extends Error {
  constructor(
    readonly status: number,
    readonly reply?: ApiError,
  ) {
    super(reply?.message ?? (status === 0 ? 'The node did not answer.' : `HTTP ${status}`));
  }

  /** The Varlink error's name, e.g. `org.sparewall.Firewall.PermissionDenied`. */
  get error(): string | undefined {
    return this.reply?.error;
  }

  /**
   * Refused for want of a session or token (it ended, or there never was
   * one), as opposed to a role that does not allow the call.
   */
  get unauthenticated(): boolean {
    if (this.status === 401) return true;
    const role = (this.reply?.parameters as { role?: unknown } | undefined)?.role;
    return this.error === 'org.sparewall.Firewall.PermissionDenied' && role === 'none';
  }
}

function isApiError(v: unknown): v is ApiError {
  return (
    typeof v === 'object' && v !== null && typeof (v as { error?: unknown }).error === 'string'
  );
}

export function failure(e: unknown): CallFailed {
  if (e instanceof CallFailed) return e;
  if (e instanceof HttpErrorResponse) {
    return new CallFailed(e.status, isApiError(e.error) ? e.error : undefined);
  }
  return new CallFailed(0);
}

/**
 * The records of an RFC 7464 JSON text sequence (each one RS, JSON, LF),
 * as they arrive in `chunks`. A record is taken as soon as its LF
 * arrives, not when the next one starts: an event stream may stay quiet.
 */
export async function* jsonSeq(chunks: AsyncIterable<string>): AsyncGenerator<unknown> {
  let buffer = '';
  const take = function* (final: boolean) {
    const parts = buffer.split('\x1e');
    buffer = parts.pop() ?? '';
    for (const p of parts) {
      if (p.trim()) yield JSON.parse(p) as unknown;
    }
    // The last record is whole once it ends in LF and parses (a pretty
    // printed one may hold LFs of its own).
    if (buffer.trim() && (final || buffer.endsWith('\n'))) {
      try {
        const v: unknown = JSON.parse(buffer);
        buffer = '';
        yield v;
      } catch (e) {
        if (final) throw e;
      }
    }
  };
  for await (const chunk of chunks) {
    buffer += chunk;
    yield* take(false);
  }
  yield* take(true);
}

async function* text(body: ReadableStream<Uint8Array>): AsyncGenerator<string> {
  const reader = body.getReader();
  const decoder = new TextDecoder();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return;
      yield decoder.decode(value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }
}

/** Calls to the node's HTTP API (docs/api), as the signed-in user. */
@Service()
export class ApiClient {
  private readonly http = inject(HttpClient);

  async call<M extends Method>(method: M, parameters?: Parameters<M>): Promise<Reply<M>> {
    try {
      return await firstValueFrom(this.http.post<Reply<M>>(callUrl(method), parameters ?? {}));
    } catch (e) {
      throw failure(e);
    }
  }

  /**
   * A streaming call's replies as they come, until the node ends the
   * stream or `signal` aborts it. An error record ends it with that error.
   */
  async *stream<M extends StreamingMethod>(
    method: M,
    parameters: Parameters<M>,
    signal: AbortSignal,
  ): AsyncGenerator<Reply<M>> {
    let r: Response;
    try {
      r = await fetch(`${callUrl(method)}?more=true`, {
        method: 'POST',
        headers: { [REQUEST_HEADER]: '1', 'Content-Type': 'application/json' },
        body: JSON.stringify(parameters),
        credentials: 'same-origin',
        signal,
      });
    } catch (e) {
      if (signal.aborted) return;
      throw new CallFailed(0);
    }
    if (!r.ok || !r.body) {
      const reply: unknown = await r.json().catch(() => undefined);
      throw new CallFailed(r.status, isApiError(reply) ? reply : undefined);
    }
    for await (const record of jsonSeq(text(r.body))) {
      if (isApiError(record)) throw new CallFailed(200, record);
      yield record as Reply<M>;
    }
  }
}
