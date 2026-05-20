import { OsvVulnerabilitySchema, type OsvVulnerability } from '../core/types.js';
import { z } from 'zod';

const OSV_API_BASE = 'https://api.osv.dev/v1';

// OSV querybatch accepts at most 1000 queries per request.
const BATCH_LIMIT = 1000;

// Per-request timeout. OSV is usually fast; a hung socket must not stall a scan.
const REQUEST_TIMEOUT_MS = 30_000;

// A failed request is retried up to this many times (so MAX_RETRIES + 1 attempts).
const MAX_RETRIES = 3;

// Upper bound on concurrent detail queries, so a vuln-heavy project does not
// fire hundreds of simultaneous requests at the OSV API.
const DETAIL_QUERY_CONCURRENCY = 8;

const OsvQueryResponseSchema = z.object({
  vulns: z.array(OsvVulnerabilitySchema).optional(),
});

const OsvBatchResponseSchema = z.object({
  results: z.array(
    z.object({
      vulns: z.array(z.object({ id: z.string(), modified: z.string().optional() })).optional(),
    }),
  ),
});

/**
 * Fetches vulnerability information for a package from the OSV API.
 * No authentication required. https://osv.dev/docs/
 */
export async function queryByPackage(
  ecosystem: string,
  packageName: string,
  version?: string,
): Promise<readonly OsvVulnerability[]> {
  const body: Record<string, unknown> = {
    package: { ecosystem, name: packageName },
  };
  if (version !== undefined) {
    body['version'] = version;
  }

  const data = await postJson(`${OSV_API_BASE}/query`, body);
  const parsed = OsvQueryResponseSchema.parse(data);

  return parsed.vulns ?? [];
}

/**
 * Queries the OSV API in bulk via /v1/querybatch. The batch endpoint only
 * returns vulnerability IDs, so any package with a hit is re-queried with
 * queryByPackage to obtain full details (summary, severity, affected ranges).
 *
 * Returns a map keyed by `name@version`, containing only vulnerable packages.
 */
export async function queryBatch(
  ecosystem: string,
  packages: readonly { name: string; version: string }[],
): Promise<Map<string, readonly OsvVulnerability[]>> {
  const vulnerable: { name: string; version: string }[] = [];

  for (let offset = 0; offset < packages.length; offset += BATCH_LIMIT) {
    const slice = packages.slice(offset, offset + BATCH_LIMIT);
    const queries = slice.map((pkg) => ({
      package: { ecosystem, name: pkg.name },
      version: pkg.version,
    }));

    const data = await postJson(`${OSV_API_BASE}/querybatch`, { queries });
    const parsed = OsvBatchResponseSchema.parse(data);

    parsed.results.forEach((result, index) => {
      const hasVulns = result.vulns !== undefined && result.vulns.length > 0;
      const pkg = slice[index];
      if (hasVulns && pkg !== undefined) {
        vulnerable.push(pkg);
      }
    });
  }

  // Detail queries are bounded so a vuln-heavy project does not overwhelm OSV.
  const detailed = await mapWithConcurrency(vulnerable, DETAIL_QUERY_CONCURRENCY, async (pkg) => {
    const vulns = await queryByPackage(ecosystem, pkg.name, pkg.version);
    return [`${pkg.name}@${pkg.version}`, vulns] as const;
  });

  return new Map(detailed);
}

// --- HTTP helpers ---

/**
 * POSTs a JSON body to an OSV endpoint and returns the parsed JSON response.
 *
 * Applies a per-request timeout and retries transient failures — network
 * errors, timeouts, HTTP 429, and 5xx — with exponential backoff. A
 * `Retry-After` header is honored when present. Non-retryable HTTP errors
 * (e.g. 4xx other than 429) fail immediately.
 */
async function postJson(url: string, body: unknown): Promise<unknown> {
  let lastError: Error | undefined;
  let waitMs = 0;

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    if (waitMs > 0) {
      await delay(waitMs);
    }

    let response: Response;
    try {
      response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (cause) {
      // Network failure or timeout — retry while attempts remain.
      lastError = new Error(`OSV API request failed: ${describeError(cause)}`);
      waitMs = backoffMs(attempt);
      continue;
    }

    if (response.ok) {
      const data: unknown = await response.json();
      return data;
    }

    lastError = new Error(`OSV API error: ${response.status.toString()} ${response.statusText}`);
    if (!isRetryableStatus(response.status)) {
      throw lastError;
    }
    waitMs = retryAfterMs(response.headers.get('retry-after')) ?? backoffMs(attempt);
  }

  throw lastError ?? new Error('OSV API request failed');
}

/** A 429 (rate limit) or any 5xx is considered transient and worth retrying. */
function isRetryableStatus(status: number): boolean {
  return status === 429 || (status >= 500 && status <= 599);
}

/** Exponential backoff with jitter: roughly 0.5s, 1s, 2s between attempts. */
function backoffMs(attempt: number): number {
  return 500 * 2 ** attempt + Math.random() * 250;
}

/**
 * Parses a `Retry-After` header into milliseconds. Supports both the
 * delta-seconds form (`120`) and the HTTP-date form. Returns undefined when
 * the header is absent or unparseable.
 */
function retryAfterMs(headerValue: string | null): number | undefined {
  if (headerValue === null) {
    return undefined;
  }
  const seconds = Number(headerValue);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return seconds * 1000;
  }
  const dateMs = Date.parse(headerValue);
  if (!Number.isNaN(dateMs)) {
    return Math.max(0, dateMs - Date.now());
  }
  return undefined;
}

function describeError(cause: unknown): string {
  return cause instanceof Error ? cause.message : String(cause);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Maps over items running at most `limit` async operations at a time.
 * Results preserve input order.
 */
async function mapWithConcurrency<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = new Array<R>(items.length);
  let cursor = 0;

  async function worker(): Promise<void> {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      const item = items[index];
      if (item === undefined) continue;
      results[index] = await fn(item);
    }
  }

  const workerCount = Math.min(limit, items.length);
  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return results;
}
