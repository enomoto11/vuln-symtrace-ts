// Type-only import of semver. It is erased at compile time, so semver must
// stay impact: not-affected even though this import statement exists.
import type { SemVer } from 'semver';

export type Version = SemVer;
