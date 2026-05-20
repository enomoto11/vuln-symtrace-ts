// Imports lodash via a subpath specifier (`lodash/get`) rather than the bare
// package name. lodash is already a direct dependency, so this must still
// resolve to lodash -> impact: needs-review.
// Regression guard: subpath imports were once missed and wrongly reported as
// not-affected.
import get from 'lodash/get';

export function pick(obj: object, path: string): unknown {
  return get(obj, path);
}
