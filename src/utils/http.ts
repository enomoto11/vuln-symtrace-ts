// Per-request timeout. A hung socket must not stall the caller indefinitely.
const REQUEST_TIMEOUT_MS = 30_000;

// A failed request is retried up to this many times (so MAX_RETRIES + 1 attempts).
const MAX_RETRIES = 3;

export interface PostJsonOptions {
  /**
   * Prefix for thrown error messages, identifying the service being called
   * (e.g. `"OSV API"`). Defaults to `"HTTP"`.
   */
  readonly errorLabel?: string;
}

/**
 * POSTs a JSON body to `url` and returns the parsed JSON response.
 *
 * Applies a per-request timeout and retries transient failures — network
 * errors, timeouts, HTTP 429, and 5xx — with exponential backoff. A
 * `Retry-After` header is honored when present. Non-retryable HTTP errors
 * (e.g. 4xx other than 429) fail immediately.
 */
export async function postJson(
  url: string,
  body: unknown,
  options: PostJsonOptions = {},
): Promise<unknown> {
  const label = options.errorLabel ?? 'HTTP';
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
      lastError = new Error(`${label} request failed: ${describeError(cause)}`);
      waitMs = backoffMs(attempt);
      continue;
    }

    if (response.ok) {
      const data: unknown = await response.json();
      return data;
    }

    lastError = new Error(`${label} error: ${response.status.toString()} ${response.statusText}`);
    if (!isRetryableStatus(response.status)) {
      throw lastError;
    }
    waitMs = retryAfterMs(response.headers.get('retry-after')) ?? backoffMs(attempt);
  }

  throw lastError ?? new Error(`${label} request failed`);
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
