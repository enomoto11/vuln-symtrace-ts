import { merge } from 'lodash';

// lodash is a direct dependency AND imported here -> expected impact: needs-review
export function combine(a: object, b: object): object {
  return merge({}, a, b);
}
