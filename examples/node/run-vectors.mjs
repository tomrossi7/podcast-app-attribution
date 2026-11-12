// Runs the verifier against every test vector.
//
//   node examples/node/run-vectors.mjs

import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { verify } from './verify.mjs';

const read = (name) => JSON.parse(readFileSync(new URL(`../../test-vectors/${name}`, import.meta.url), 'utf8'));
const suite = read('vectors.json');
const keys = read(suite.keys);

let failures = 0;
for (const v of suite.vectors) {
  const actual = verify({
    method: v.method,
    url: v.url,
    now: v.now,
    keysFor: (iss) => (iss === suite.issuer ? keys : null),
    audiencesFor: () => v.accepted_audiences ?? [],
  });
  const ok = isDeepStrictEqual(actual, v.expected);
  if (!ok) failures++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${v.name}${ok ? '' : `\n     expected ${JSON.stringify(v.expected)}\n     actual   ${JSON.stringify(actual)}`}`);
}
console.log(`\n${suite.vectors.length - failures} of ${suite.vectors.length} passed`);
process.exit(failures ? 1 : 0);
