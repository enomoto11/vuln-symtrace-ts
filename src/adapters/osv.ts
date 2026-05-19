import { OsvVulnerabilitySchema, type OsvVulnerability } from '../core/types.js';
import { z } from 'zod';

const OSV_API_BASE = 'https://api.osv.dev/v1';

const OsvQueryResponseSchema = z.object({
  vulns: z.array(OsvVulnerabilitySchema).optional(),
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

  const response = await fetch(`${OSV_API_BASE}/query`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`OSV API error: ${response.status.toString()} ${response.statusText}`);
  }

  const data: unknown = await response.json();
  const parsed = OsvQueryResponseSchema.parse(data);

  return parsed.vulns ?? [];
}
