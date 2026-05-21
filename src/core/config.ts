import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { z } from 'zod';
import type { ScanSummary } from './scan.js';
import type { OsvVulnerability } from './types.js';

/** Config file name, looked up in the scanned project's directory. */
export const CONFIG_FILENAME = '.symtracerc.json';

/**
 * A rule that suppresses a known vulnerability from the CI exit code.
 * `id` matches an OSV vulnerability id or any of its aliases (e.g. a CVE).
 */
const IgnoreRuleSchema = z.object({
  /** OSV id, GHSA id, or CVE alias of the vulnerability to suppress. */
  id: z.string().min(1),
  /** Why this vulnerability is accepted — required so suppressions stay documented. */
  reason: z.string().min(1),
  /**
   * Optional ISO date (`YYYY-MM-DD`) after which the rule stops suppressing,
   * forcing periodic re-review. The rule is valid through the whole of this day.
   */
  expires: z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/)
    .optional(),
});

export type IgnoreRule = z.infer<typeof IgnoreRuleSchema>;

const SymtraceConfigSchema = z.object({
  ignore: z.array(IgnoreRuleSchema).optional(),
});

export type SymtraceConfig = z.infer<typeof SymtraceConfigSchema>;

/**
 * Loads `.symtracerc.json` from a project directory. Returns an empty config
 * when the file is absent. Throws a clear error when it is present but cannot
 * be parsed or fails schema validation.
 */
export function loadConfig(projectDir: string): SymtraceConfig {
  const path = resolve(projectDir, CONFIG_FILENAME);
  if (!existsSync(path)) {
    return {};
  }

  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8'));
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    throw new Error(`Failed to parse ${CONFIG_FILENAME}: ${detail}`, { cause });
  }

  const result = SymtraceConfigSchema.safeParse(raw);
  if (!result.success) {
    const detail = result.error.issues
      .map((issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`)
      .join('; ');
    throw new Error(`Invalid ${CONFIG_FILENAME}: ${detail}`);
  }
  return result.data;
}

/** The result of applying ignore rules to a scan. */
export interface IgnoreOutcome {
  /**
   * Vulnerability id → reason, for every vulnerability actively suppressed.
   * Keyed by the OSV `id`, even when a rule matched it via an alias.
   */
  readonly ignored: ReadonlyMap<string, string>;
  /**
   * Ignore rules whose `expires` date has passed. These no longer suppress
   * anything; surfacing them prompts the user to re-review or remove them.
   */
  readonly expired: readonly IgnoreRule[];
}

/**
 * Applies ignore rules to a scan summary, relative to the current date `now`.
 *
 * A rule suppresses a vulnerability when its `id` equals the vulnerability's
 * OSV id or one of its aliases, and the rule has not expired. Expired rules
 * are collected separately and never suppress.
 */
export function applyIgnoreRules(
  summary: ScanSummary,
  rules: readonly IgnoreRule[],
  now: Date,
): IgnoreOutcome {
  const expired = rules.filter((rule) => isExpired(rule, now));
  const active = rules.filter((rule) => !isExpired(rule, now));

  const ignored = new Map<string, string>();
  for (const vp of summary.vulnerablePackages) {
    for (const vuln of vp.vulnerabilities) {
      const rule = active.find((r) => ruleMatchesVuln(r, vuln));
      if (rule !== undefined) {
        ignored.set(vuln.id, rule.reason);
      }
    }
  }

  return { ignored, expired };
}

/** A rule matches when its id is the vulnerability's OSV id or one of its aliases. */
function ruleMatchesVuln(rule: IgnoreRule, vuln: OsvVulnerability): boolean {
  return rule.id === vuln.id || (vuln.aliases ?? []).includes(rule.id);
}

/** A rule is expired once `now` is past the end of its `expires` day. */
function isExpired(rule: IgnoreRule, now: Date): boolean {
  if (rule.expires === undefined) {
    return false;
  }
  const endOfDay = Date.parse(`${rule.expires}T23:59:59.999Z`);
  return Number.isFinite(endOfDay) && now.getTime() > endOfDay;
}
