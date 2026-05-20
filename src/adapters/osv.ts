import { OsvVulnerabilitySchema, type OsvVulnerability } from '../core/types.js';
import { postJson } from '../utils/http.js';
import { mapWithConcurrency } from '../utils/concurrency.js';
import { z } from 'zod';

const OSV_API_BASE = 'https://api.osv.dev/v1';

// OSV querybatch accepts at most 1000 queries per request.
const BATCH_LIMIT = 1000;

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

  const data = await postJson(`${OSV_API_BASE}/query`, body, { errorLabel: 'OSV API' });
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

    const data = await postJson(
      `${OSV_API_BASE}/querybatch`,
      { queries },
      { errorLabel: 'OSV API' },
    );
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
