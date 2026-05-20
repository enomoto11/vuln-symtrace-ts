import { z } from 'zod';

// --- Partial schema for OSV API response ---

export const SeveritySchema = z.object({
  type: z.enum(['CVSS_V3', 'CVSS_V4']),
  score: z.string(),
});

export const AffectedRangeSchema = z.object({
  type: z.enum(['ECOSYSTEM', 'SEMVER', 'GIT']),
  events: z.array(z.record(z.string(), z.string())),
});

export const AffectedPackageSchema = z.object({
  package: z.object({
    ecosystem: z.string(),
    name: z.string(),
  }),
  ranges: z.array(AffectedRangeSchema).optional(),
  versions: z.array(z.string()).optional(),
});

export const OsvVulnerabilitySchema = z.object({
  id: z.string(),
  summary: z.string().optional(),
  details: z.string().optional(),
  aliases: z.array(z.string()).optional(),
  severity: z.array(SeveritySchema).optional(),
  affected: z.array(AffectedPackageSchema).optional(),
  references: z
    .array(
      z.object({
        type: z.string(),
        url: z.string(),
      }),
    )
    .optional(),
});

export type OsvVulnerability = z.infer<typeof OsvVulnerabilitySchema>;

// --- vuln-scope internal model ---

export interface InstalledPackage {
  readonly name: string;
  readonly version: string;
  readonly isDirect: boolean;
}

export interface RepoConfig {
  readonly name: string;
  readonly path: string;
  readonly tsconfig: string;
}

export interface VulnScopeConfig {
  readonly repos: readonly RepoConfig[];
  readonly severityThreshold: 'low' | 'moderate' | 'high' | 'critical';
}

export interface CodeUsage {
  readonly file: string;
  readonly line: number;
  readonly column: number;
  readonly code: string;
  readonly symbol: string;
}

export type ImpactLevel = 'affected' | 'needs-review' | 'not-affected' | 'transitive';

export interface RepoImpact {
  readonly repo: RepoConfig;
  readonly installedVersion: string | undefined;
  readonly impact: ImpactLevel;
  readonly usages: readonly CodeUsage[];
}

export interface ScanResult {
  readonly vulnerability: OsvVulnerability;
  readonly packageName: string;
  readonly repoImpacts: readonly RepoImpact[];
  readonly scannedAt: Date;
}
