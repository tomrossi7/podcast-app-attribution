// Runs the verifier against every test vector, or only the ones named.
//
//   node examples/node/run-vectors.mjs
//   node examples/node/run-vectors.mjs per-request expired

import { readFileSync } from 'node:fs';
import { isDeepStrictEqual } from 'node:util';
import { verify } from './verify.mjs';

const read = (name) => JSON.parse(readFileSync(new URL(`../../test-vectors/${name}`, import.meta.url), 'utf8'));
const suite = read('vectors.json');
const keys = read(suite.keys);

const names = process.argv.slice(2);
const unknown = names.filter((name) => !suite.vectors.some((v) => v.name === name));
if (unknown.length) {
  console.error(`no such vector: ${unknown.join(', ')}`);
  process.exit(2);
}
const vectors = names.length ? suite.vectors.filter((v) => names.includes(v.name)) : suite.vectors;

let failures = 0;
for (const v of vectors) {
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
console.log(`\n${vectors.length - failures} of ${vectors.length} passed`);
process.exit(failures ? 1 : 0);
