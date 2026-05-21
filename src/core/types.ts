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
  // GitHub advisories expose a severity label (LOW/MODERATE/HIGH/CRITICAL) here.
  database_specific: z.object({ severity: z.string().optional() }).optional(),
});

export type OsvVulnerability = z.infer<typeof OsvVulnerabilitySchema>;

// --- vuln-symtrace-ts internal model ---

export interface InstalledPackage {
  readonly name: string;
  readonly version: string;
  readonly isDirect: boolean;
}

/**
 * How an exported symbol of a vulnerable package is referenced at a site:
 * - `import`        — the import/re-export statement itself (no resolved reference)
 * - `call`          — the export is called, e.g. `merge(a, b)`
 * - `member-access` — reached via property access, e.g. `_.merge`
 * - `reference`     — any other identifier reference (passed as an argument, etc.)
 * - `re-export`     — forwarded by `export ... from`
 */
export type ReferenceKind = 'import' | 'call' | 'member-access' | 'reference' | 're-export';

/** A single reference to an exported symbol of a vulnerable package. */
export interface ExportUsage {
  /** Exported symbol name, or null when it cannot be determined (e.g. `export *`). */
  readonly exportName: string | null;
  readonly kind: ReferenceKind;
  readonly file: string;
  readonly line: number;
  readonly column: number;
  readonly code: string;
}

export interface CodeUsage {
  readonly file: string;
  readonly line: number;
  readonly column: number;
  readonly code: string;
  readonly symbol: string;
  /** Exports of the package used through this import / re-export site. */
  readonly exportUsages: readonly ExportUsage[];
}

/** A package export aggregated across all of its reference sites. */
export interface UsedExport {
  /** Exported symbol name, or null when it cannot be determined. */
  readonly name: string | null;
  readonly refs: readonly ExportUsage[];
}

/**
 * Soft, non-authoritative triage hint for a needs-review vulnerability:
 * - `review-priority` — the code uses an export the advisory names as vulnerable
 * - `likely-low`      — the advisory names exports, but the code uses none of them
 * - `needs-review`    — the advisory names no export, so there is nothing to compare
 */
export type SoftHint = 'review-priority' | 'likely-low' | 'needs-review';

/**
 * Cross-reference between the exports a project uses and the API names an
 * advisory's text mentions, for one vulnerability. Never authoritative — it
 * informs prioritisation, it does not decide whether the code is affected.
 */
export interface AdvisoryEvidence {
  /** OSV / GHSA id this evidence belongs to. */
  readonly vulnId: string;
  /** Code identifiers extracted from the advisory text (may be empty). */
  readonly mentionedApis: readonly string[];
  /** Used export names that overlap with `mentionedApis` (case-insensitive). */
  readonly overlap: readonly string[];
  /** The triage hint derived from the overlap. */
  readonly hint: SoftHint;
}

export type ImpactLevel = 'needs-review' | 'not-affected' | 'transitive';

export type SeverityLevel = 'low' | 'moderate' | 'high' | 'critical';
