import { describe, it, expect, vi, afterEach } from 'vitest';
import { queryByPackage, queryBatch } from '../src/adapters/osv.js';

function jsonResponse(data: unknown): Response {
  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe('queryByPackage — retry behavior', () => {
  it('retries an HTTP 429 response and then succeeds', async () => {
    let calls = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(() => {
        calls += 1;
        return Promise.resolve(
          calls === 1
            ? new Response('rate limited', { status: 429 })
            : jsonResponse({ vulns: [{ id: 'GHSA-x' }] }),
        );
      }),
    );

    vi.useFakeTimers();
    const promise = queryByPackage('npm', 'lodash');
    await vi.advanceTimersByTimeAsync(5_000);
    const vulns = await promise;

    expect(calls).toBe(2);
    expect(vulns).toHaveLength(1);
  });

  it('retries after a network error and then succeeds', async () => {
    let calls = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(() => {
        calls += 1;
        return calls === 1
          ? Promise.reject(new Error('ECONNRESET'))
          : Promise.resolve(jsonResponse({ vulns: [] }));
      }),
    );

    vi.useFakeTimers();
    const promise = queryByPackage('npm', 'lodash');
    await vi.advanceTimersByTimeAsync(5_000);
    await promise;

    expect(calls).toBe(2);
  });

  it('honors a Retry-After header before retrying', async () => {
    let calls = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(() => {
        calls += 1;
        return Promise.resolve(
          calls === 1
            ? new Response('slow down', {
                status: 429,
                headers: { 'Retry-After': '5' },
              })
            : jsonResponse({ vulns: [] }),
        );
      }),
    );

    vi.useFakeTimers();
    const promise = queryByPackage('npm', 'lodash');

    // The 5s Retry-After window has not elapsed yet — no second attempt.
    await vi.advanceTimersByTimeAsync(3_000);
    expect(calls).toBe(1);

    await vi.advanceTimersByTimeAsync(3_000);
    await promise;
    expect(calls).toBe(2);
  });

  it('throws after exhausting retries on repeated HTTP 503', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(new Response('err', { status: 503 })));
    vi.stubGlobal('fetch', fetchMock);

    vi.useFakeTimers();
    const promise = queryByPackage('npm', 'lodash');
    const rejection = expect(promise).rejects.toThrow(/OSV API error: 503/);
    await vi.advanceTimersByTimeAsync(30_000);
    await rejection;

    // 1 initial attempt + 3 retries.
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });

  it('does not retry a non-retryable HTTP 400', async () => {
    const fetchMock = vi.fn(() => Promise.resolve(new Response('bad request', { status: 400 })));
    vi.stubGlobal('fetch', fetchMock);

    await expect(queryByPackage('npm', 'lodash')).rejects.toThrow(/OSV API error: 400/);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe('queryBatch — concurrency limit', () => {
  it('caps concurrent detail queries instead of firing them all at once', async () => {
    const HIT_COUNT = 25;
    let active = 0;
    let peak = 0;

    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        if (url.endsWith('/querybatch')) {
          return jsonResponse({
            results: Array.from({ length: HIT_COUNT }, () => ({ vulns: [{ id: 'V' }] })),
          });
        }
        // A /query detail call: observe how many run at the same time.
        active += 1;
        peak = Math.max(peak, active);
        await Promise.resolve();
        active -= 1;
        return jsonResponse({ vulns: [{ id: 'GHSA-x' }] });
      }),
    );

    const packages = Array.from({ length: HIT_COUNT }, (_, i) => ({
      name: `pkg-${i.toString()}`,
      version: '1.0.0',
    }));
    const result = await queryBatch('npm', packages);

    expect(result.size).toBe(HIT_COUNT);
    expect(peak).toBeGreaterThan(1); // requests genuinely run in parallel
    expect(peak).toBeLessThanOrEqual(8); // ...but never beyond the cap
  });
});
