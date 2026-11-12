// Regenerates vectors.json (and the sample keys, if they are missing).
//
//   node test-vectors/generate.mjs
//
// ECDSA signatures are randomized, so every run produces different tokens. All of them are
// equally valid; the expected results do not change.

import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { decode, encode, Tagged } from '../examples/node/cbor.mjs';
import { ALG, AUD, CATM, CATU, CATV, CTI, EXP, IAT, ISS, KID, NBF, algorithmFor, exactUrl, signCose, toBase64Url } from '../examples/node/sign.mjs';

const here = (name) => new URL(name, import.meta.url);

const ISSUER = 'https://exampleplayer.com';
const ES_KID = '2026-11';
const ED_KID = '2026-11-ed';
const IAT_TIME = 1800000000; // 2027-01-15T08:00:00Z
const NOW = IAT_TIME + 60;
const EPISODE = 'https://host.example/show/episode.mp3';

// --- keys -----------------------------------------------------------------------------------

if (!existsSync(here('keys.json'))) {
  const es = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const ed = generateKeyPairSync('ed25519');
  const jwk = (key, kid) => ({ ...key.export({ format: 'jwk' }), use: 'sig', kid });
  writeJson('keys.json', { keys: [jwk(es.publicKey, ES_KID), jwk(ed.publicKey, ED_KID)] });
  writeJson('private-keys.json', { keys: [jwk(es.privateKey, ES_KID), jwk(ed.privateKey, ED_KID)] });
}
const privateKeys = JSON.parse(readFileSync(here('private-keys.json'), 'utf8')).keys;
const esKey = privateKeys.find((k) => k.kid === ES_KID);
const edKey = privateKeys.find((k) => k.kid === ED_KID);
const strangerKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' });

// --- building tokens ------------------------------------------------------------------------

// The required claims, with overrides. An override of `undefined` removes the claim.
function claims(overrides = {}) {
  const map = new Map([
    [ISS, ISSUER],
    [EXP, IAT_TIME + 300],
    [IAT, IAT_TIME],
    [CTI, randomBytes(16)],
    [CATV, 1],
  ]);
  for (const [label, value] of Object.entries(overrides)) {
    if (value === undefined) map.delete(Number(label));
    else map.set(Number(label), value);
  }
  return map;
}

function cose({ payload, key = esKey, kid = ES_KID, kidIn = 'protected', tags = [18], protectedExtra = [], unprotectedExtra = [] }) {
  const kidEntry = [KID, Buffer.from(kid, 'utf8')];
  const protectedHeader = new Map([[ALG, algorithmFor(key)], ...(kidIn === 'protected' ? [kidEntry] : []), ...protectedExtra]);
  const unprotectedHeader = new Map([...(kidIn === 'unprotected' ? [kidEntry] : []), ...unprotectedExtra]);
  let item = signCose({ protectedHeader, unprotectedHeader, payload, privateJwk: key });
  for (const tag of tags) item = new Tagged(tag, item);
  return encode(item);
}

const token = (options = {}) => cose({ ...options, payload: encode(options.claims ?? claims()) });

function attach(url, bytes, { padded = false } = {}) {
  const value = padded ? Buffer.from(bytes).toString('base64').replace(/\+/g, '-').replace(/\//g, '_') : toBase64Url(bytes);
  return url + (url.includes('?') ? '&' : '?') + 'CAT=' + value;
}

const exact = (value) => new Map([[0, value]]);
const verified = (restrictions = {}) => ({
  verified: true,
  iss: ISSUER,
  kid: ES_KID,
  exp: IAT_TIME + 300,
  catu: null,
  catm: null,
  aud: null,
  ...restrictions,
});
const unverified = (reason) => ({ verified: false, reason });

// --- the vectors ----------------------------------------------------------------------------

const vectors = [];
function vector(name, description, { url, method = 'GET', now = NOW, expected, ...rest }) {
  vectors.push({ name, description, method, url, now, ...rest, expected, diagnostic: diagnose(url) });
}

// Verified.

{
  const url = EPISODE + '?id=42';
  vector('per-request', 'The recommended pattern: bound to one URL with catu and to GET/HEAD with catm. Tag 18, kid in the protected header. The URL already has a query; CAT is appended after it.', {
    url: attach(url, token({ claims: claims({ [CATU]: exactUrl(url), [CATM]: ['GET', 'HEAD'] }) })),
    expected: verified({ catu: true, catm: true }),
  });
}

vector('session', 'Only the required claims. Good for any URL on any host until it expires.', {
  url: attach(EPISODE, token()),
  expected: verified(),
});

vector('session-head', 'The same kind of token on a HEAD request.', {
  url: attach(EPISODE, token()),
  method: 'HEAD',
  expected: verified(),
});

vector('lifetime-24-hours', 'The longest lifetime allowed (exp = iat + 86400), checked one second before it expires.', {
  url: attach(EPISODE, token({ claims: claims({ [EXP]: IAT_TIME + 86400 }) })),
  now: IAT_TIME + 86399,
  expected: verified({ exp: IAT_TIME + 86400 }),
});

vector('kid-unprotected', 'kid in the unprotected header, CWT tag 61 around COSE tag 18, and nbf equal to iat.', {
  url: attach(EPISODE, token({ claims: claims({ [NBF]: IAT_TIME }), kidIn: 'unprotected', tags: [18, 61] })),
  expected: verified(),
});

{
  // Pick a token whose length needs base64 padding.
  let bytes;
  for (let n = 16; ; n++) {
    bytes = token({ claims: claims({ [CTI]: randomBytes(n) }), tags: [] });
    if (bytes.length % 3 !== 0) break;
  }
  vector('untagged-padded', 'An untagged COSE_Sign1, base64url-encoded with "=" padding.', {
    url: attach(EPISODE, bytes, { padded: true }),
    expected: verified(),
  });
}

vector('aud-origin', 'aud names the origin the request arrived on.', {
  url: attach(EPISODE, token({ claims: claims({ [AUD]: 'https://host.example' }) })),
  expected: verified({ aud: true }),
});

vector('aud-configured', 'aud is a value the host has configured as acceptable for this issuer.', {
  url: attach(EPISODE, token({ claims: claims({ [AUD]: 'urn:example:podcast-hosts' }) })),
  accepted_audiences: ['urn:example:podcast-hosts'],
  expected: verified({ aud: true }),
});

vector('catu-normalized', 'The request URL is matched after normalization: scheme and host lowercased, default port removed, dot segments resolved, "%7E" decoded to "~". The catu port component is the empty string.', {
  url: attach('HTTPS://Host.Example:443/show/extra/../%7Eepisode.mp3', token({
    claims: claims({ [CATU]: new Map([[0, exact('https')], [1, exact('host.example')], [2, exact('')], [3, exact('/show/~episode.mp3')]]) }),
  })),
  expected: verified({ catu: true }),
});

vector('catu-verbatim', 'The issuer bound the query exactly as written ("q=%7e") rather than normalized ("q=~"). The normalized comparison fails; the second comparison, with the path and query as received, succeeds.', {
  url: attach(EPISODE + '?q=%7e', token({
    claims: claims({ [CATU]: new Map([[0, exact('https')], [1, exact('host.example')], [3, exact('/show/episode.mp3')], [4, exact('q=%7e')]]) }),
  })),
  expected: verified({ catu: true }),
});

vector('catu-prefix', 'catu restricts the host exactly and the path by prefix, so the token covers a whole show.', {
  url: attach(EPISODE, token({ claims: claims({ [CATU]: new Map([[1, exact('host.example')], [3, new Map([[1, '/show/']])]]) }) })),
  expected: verified({ catu: true }),
});

vector('eddsa', 'Signed with Ed25519 (alg -8). Hosts MAY support EdDSA; one that does not reports "malformed".', {
  url: attach(EPISODE, token({ key: edKey, kid: ED_KID })),
  requires: 'EdDSA',
  expected: verified({ kid: ED_KID }),
});

// Unverified: time.

vector('expired', 'now equals exp. A token is valid only while now < exp.', {
  url: attach(EPISODE, token()),
  now: IAT_TIME + 300,
  expected: unverified('expired'),
});

vector('not-yet-valid', 'nbf is one second in the future. No clock-skew leeway is allowed.', {
  url: attach(EPISODE, token({ claims: claims({ [NBF]: NOW + 1 }) })),
  expected: unverified('not_yet_valid'),
});

vector('lifetime-too-long', 'exp is more than 24 hours after iat.', {
  url: attach(EPISODE, token({ claims: claims({ [EXP]: IAT_TIME + 86401 }) })),
  expected: unverified('malformed'),
});

// Unverified: keys and signature.

{
  const bytes = Buffer.from(token());
  bytes[bytes.length - 1] ^= 0x01;
  vector('bad-signature', 'A valid token with the last bit of its signature flipped.', {
    url: attach(EPISODE, bytes),
    expected: unverified('bad_signature'),
  });
}

vector('wrong-key', 'Signed by a key that is not the published one, under the published kid.', {
  url: attach(EPISODE, token({ key: strangerKey })),
  expected: unverified('bad_signature'),
});

vector('unknown-kid', 'The kid is not in the issuer\'s key set.', {
  url: attach(EPISODE, token({ kid: '2020-01' })),
  expected: unverified('key_unavailable'),
});

vector('unknown-issuer', 'A well-formed token from an issuer the host has no cached keys for. The host answers without fetching.', {
  url: attach(EPISODE, token({ claims: claims({ [ISS]: 'https://unknown.example' }), key: strangerKey })),
  expected: unverified('key_unavailable'),
});

vector('kid-names-wrong-key-type', 'An ES256 token whose kid names the Ed25519 key. A key that does not fit the token\'s algorithm is treated as absent.', {
  url: attach(EPISODE, token({ kid: ED_KID })),
  expected: unverified('key_unavailable'),
});

{
  const bytes = Buffer.from(token());
  bytes[bytes.length - 1] ^= 0x01;
  vector('expired-before-signature', 'Expired and badly signed. Claims and time are checked before the key is looked up, so the reason is "expired".', {
    url: attach(EPISODE, bytes),
    now: IAT_TIME + 600,
    expected: unverified('expired'),
  });
}

// Unverified: restrictions.

vector('url-mismatch', 'catu binds the token to a different episode.', {
  url: attach(EPISODE, token({ claims: claims({ [CATU]: exactUrl('https://host.example/show/other.mp3') }) })),
  expected: unverified('url_mismatch'),
});

vector('url-mismatch-port-443', 'catu asks for port "443". Normalization removes the default port, so the port component is the empty string and this never matches. The as-received fallback covers path and query only.', {
  url: attach('https://host.example:443/show/episode.mp3', token({ claims: claims({ [CATU]: new Map([[0, exact('https')], [2, exact('443')]]) }) })),
  expected: unverified('url_mismatch'),
});

vector('method-mismatch', 'catm allows GET and HEAD; the request is a POST.', {
  url: attach(EPISODE, token({ claims: claims({ [CATM]: ['GET', 'HEAD'] }) })),
  method: 'POST',
  expected: unverified('method_mismatch'),
});

vector('audience-mismatch', 'aud names another host.', {
  url: attach(EPISODE, token({ claims: claims({ [AUD]: 'https://other.example' }) })),
  expected: unverified('audience_mismatch'),
});

// Unverified: malformed.

vector('missing-cti', 'A required claim is absent.', {
  url: attach(EPISODE, token({ claims: claims({ [CTI]: undefined }) })),
  expected: unverified('malformed'),
});

vector('short-cti', 'cti is 4 bytes; at least 8 are required.', {
  url: attach(EPISODE, token({ claims: claims({ [CTI]: randomBytes(4) }) })),
  expected: unverified('malformed'),
});

vector('catv-2', 'An unsupported CAT version.', {
  url: attach(EPISODE, token({ claims: claims({ [CATV]: 2 }) })),
  expected: unverified('malformed'),
});

vector('iss-with-path', 'iss has a trailing slash, so it is not a bare origin.', {
  url: attach(EPISODE, token({ claims: claims({ [ISS]: ISSUER + '/' }) })),
  expected: unverified('malformed'),
});

vector('iss-not-https', 'iss uses http.', {
  url: attach(EPISODE, token({ claims: claims({ [ISS]: 'http://exampleplayer.com' }) })),
  expected: unverified('malformed'),
});

vector('unsupported-alg', 'The protected header says ES384 (alg -35).', {
  url: attach(EPISODE, (() => {
    const payload = encode(claims());
    const [, unprotectedHeader, , signature] = signCose({ protectedHeader: new Map(), payload, privateJwk: esKey });
    const protectedBytes = encode(new Map([[ALG, -35], [KID, Buffer.from(ES_KID)]]));
    return encode(new Tagged(18, [protectedBytes, unprotectedHeader, payload, signature]));
  })()),
  expected: unverified('malformed'),
});

vector('kid-in-both-headers', 'kid appears in the protected and the unprotected header.', {
  url: attach(EPISODE, token({ unprotectedExtra: [[KID, Buffer.from(ES_KID)]] })),
  expected: unverified('malformed'),
});

vector('unknown-critical-header', 'The crit header lists an extension the verifier does not understand.', {
  url: attach(EPISODE, token({ protectedExtra: [[2, [-70000]], [-70000, 1]] })),
  expected: unverified('malformed'),
});

{
  // Correctly signed, but the claims map carries label 1 (iss) twice.
  const original = encode(claims());
  const payload = Buffer.concat([Buffer.from([original[0] + 1]), original.subarray(1), encode(ISS), encode('https://other.example')]);
  vector('duplicate-claim', 'The claims map contains iss twice. The signature is valid; the token is still rejected.', {
    url: attach(EPISODE, cose({ payload })),
    expected: unverified('malformed'),
  });
}

vector('trailing-data', 'A valid token followed by one extra byte.', {
  url: attach(EPISODE, Buffer.concat([token(), Buffer.from([0x00])])),
  expected: unverified('malformed'),
});

vector('not-base64url', 'The CAT value is not base64url.', {
  url: EPISODE + '?CAT=not*a*token',
  expected: unverified('malformed'),
});

vector('two-cat-parameters', 'Two CAT parameters, each a valid token. More than one is ambiguous, so the request is unverified.', {
  url: attach(attach(EPISODE, token()), token()),
  expected: unverified('malformed'),
});

writeJson('vectors.json', {
  specification: 'Verified App Attribution, Draft 0.1',
  issuer: ISSUER,
  keys: 'keys.json',
  vectors,
});
console.log(`wrote ${vectors.length} vectors`);

// --- helpers --------------------------------------------------------------------------------

function writeJson(name, value) {
  writeFileSync(here(name), JSON.stringify(value, null, 2) + '\n');
}

// CBOR diagnostic notation for the first CAT parameter, for human readers. `<< … >>` marks a
// byte string whose content is itself CBOR.
function diagnose(url) {
  try {
    const value = /[?&]CAT=([^&]*)/.exec(url)[1].replace(/=+$/, '');
    let item = decode(Buffer.from(value, 'base64url'));
    const tags = [];
    while (item instanceof Tagged) {
      tags.push(item.tag);
      item = item.value;
    }
    const [protectedBytes, unprotectedHeader, payload, signature] = item;
    const body = `[${embedded(protectedBytes)}, ${diag(unprotectedHeader)}, ${embedded(payload)}, ${diag(signature)}]`;
    return tags.reduceRight((inner, tag) => `${tag}(${inner})`, body);
  } catch {
    return null;
  }
}

function embedded(bytes) {
  try {
    return `<< ${diag(decode(bytes))} >>`;
  } catch {
    return diag(bytes);
  }
}

function diag(value) {
  if (value instanceof Uint8Array) return `h'${Buffer.from(value).toString('hex')}'`;
  if (typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(diag).join(', ')}]`;
  if (value instanceof Map) return `{${[...value].map(([k, v]) => `${diag(k)}: ${diag(v)}`).join(', ')}}`;
  if (value instanceof Tagged) return `${value.tag}(${diag(value.value)})`;
  return String(value);
}
