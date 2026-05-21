// Default-imports lodash and reaches an export through member access
// (`_.merge`). lodash is already a direct dependency; this exercises
// default-import member-access resolution -> the report should list `merge`
// among the used exports.
import _ from 'lodash';

export function blend(a: object, b: object): object {
  return _.merge({}, a, b);
}
