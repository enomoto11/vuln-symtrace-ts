import { combine } from './used.js';

// minimist is a direct dependency but never imported anywhere -> expected impact: not-affected
const result = combine({ a: 1 }, { b: 2 });
console.log(result);
