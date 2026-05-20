import { combine } from './used.js';

// semver is a direct dependency but never imported anywhere -> expected impact: not-affected
// mkdirp@0.5.1 pulls in minimist@0.0.8 as a transitive dep -> expected impact: transitive
const result = combine({ a: 1 }, { b: 2 });
console.log(result);
