// Regenerates vectors.json (and the sample keys, if they are missing).
//
//   node test-vectors/generate.mjs
//
// ECDSA signatures are randomized, so every run produces different tokens. All of them are
// equally valid; the expected results do not change.

import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { decode, encode, Tagged } from '../examples/node/cbor.mjs';
import { ALG, AUD, CATM, CATU, CATV, CTI, ES256, EXP, IAT, ISS, KID, NBF, exactUrl, signCose, toBase64Url } from '../examples/node/sign.mjs';

const here = (name) => new URL(name, import.meta.url);

const ISSUER = 'https://exampleplayer.com';
const KEY_ID = '2026-11';
const ENC_KID = '2026-11-enc'; // a published key that is not for signing
const MINTED = 1800000000; // 2027-01-15T08:00:00Z
const NOW = MINTED + 60;
const WINDOW = 86400;
const EPISODE = 'https://host.example/show/episode.mp3';

// --- keys -----------------------------------------------------------------------------------

if (!existsSync(here('keys.json'))) {
  const signing = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const other = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = (key, kid, use) => ({ ...key.export({ format: 'jwk' }), use, kid });
  writeJson('keys.json', { keys: [jwk(signing.publicKey, KEY_ID, 'sig'), jwk(other.publicKey, ENC_KID, 'enc')] });
  writeJson('private-keys.json', { keys: [jwk(signing.privateKey, KEY_ID, 'sig'), jwk(other.privateKey, ENC_KID, 'enc')] });
}
const privateKeys = JSON.parse(readFileSync(here('private-keys.json'), 'utf8')).keys;
const signingKey = privateKeys.find((k) => k.kid === KEY_ID);
const encKey = privateKeys.find((k) => k.kid === ENC_KID);
const strangerKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey.export({ format: 'jwk' });

// --- building tokens ------------------------------------------------------------------------

// The required claims, with overrides. An override of `undefined` removes the claim.
function claims(overrides = {}) {
  const map = new Map([
    [ISS, ISSUER],
    [EXP, MINTED + 300],
    [CATV, 1],
  ]);
  for (const [label, value] of Object.entries(overrides)) {
    if (value === undefined) map.delete(Number(label));
    else map.set(Number(label), value);
  }
  return map;
}

function cose({ payload, key = signingKey, kid = KEY_ID, kidIn = 'protected', tags = [18], protectedExtra = [], unprotectedExtra = [] }) {
  const kidEntry = [KID, Buffer.from(kid, 'utf8')];
  const protectedHeader = new Map([[ALG, ES256], ...(kidIn === 'protected' ? [kidEntry] : []), ...protectedExtra]);
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
const verified = () => ({ verified: true, iss: ISSUER });
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
    expected: verified(),
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

vector('expires-in-24-hours', 'exp is exactly 24 hours after the request arrives, the furthest ahead a host accepts.', {
  url: attach(EPISODE, token({ claims: claims({ [EXP]: NOW + WINDOW }) })),
  expected: verified(),
});

vector('iat-and-cti', 'Carries the optional iat and cti claims, as tokens from other CAT issuers often do. They are allowed and change nothing.', {
  url: attach(EPISODE, token({ claims: claims({ [IAT]: MINTED, [CTI]: randomBytes(16) }) })),
  expected: verified(),
});

vector('kid-unprotected', 'kid in the unprotected header, CWT tag 61 around COSE tag 18, and an nbf that has passed.', {
  url: attach(EPISODE, token({ claims: claims({ [NBF]: MINTED }), kidIn: 'unprotected', tags: [18, 61] })),
  expected: verified(),
});

{
  // Pick a token whose length needs base64 padding.
  let bytes;
  for (let n = 0; ; n++) {
    bytes = token({ claims: claims(n ? { [CTI]: randomBytes(n) } : {}), tags: [] });
    if (bytes.length % 3 !== 0) break;
  }
  vector('untagged-padded', 'An untagged COSE_Sign1, base64url-encoded with "=" padding.', {
    url: attach(EPISODE, bytes, { padded: true }),
    expected: verified(),
  });
}

vector('aud-origin', 'aud names the origin the request arrived on.', {
  url: attach(EPISODE, token({ claims: claims({ [AUD]: 'https://host.example' }) })),
  expected: verified(),
});

vector('aud-configured', 'aud is a value the host has configured as acceptable for this issuer.', {
  url: attach(EPISODE, token({ claims: claims({ [AUD]: 'urn:example:podcast-hosts' }) })),
  accepted_audiences: ['urn:example:podcast-hosts'],
  expected: verified(),
});

vector('catu-normalized', 'The request URL is matched after normalization: scheme and host lowercased, default port removed, dot segments resolved, "%7E" decoded to "~". The catu port component is the empty string.', {
  url: attach('HTTPS://Host.Example:443/show/extra/../%7Eepisode.mp3', token({
    claims: claims({ [CATU]: new Map([[0, exact('https')], [1, exact('host.example')], [2, exact('')], [3, exact('/show/~episode.mp3')]]) }),
  })),
  expected: verified(),
});

vector('catu-verbatim', 'The issuer bound the query exactly as written ("q=%7e") rather than normalized ("q=~"). The normalized comparison fails; the second comparison, with the path and query as received, succeeds.', {
  url: attach(EPISODE + '?q=%7e', token({
    claims: claims({ [CATU]: new Map([[0, exact('https')], [1, exact('host.example')], [3, exact('/show/episode.mp3')], [4, exact('q=%7e')]]) }),
  })),
  expected: verified(),
});

vector('catu-prefix', 'catu restricts the host exactly and the path by prefix, so the token covers a whole show. Prefix matching is optional for hosts; one that does not support it reports the request as unverified.', {
  url: attach(EPISODE, token({ claims: claims({ [CATU]: new Map([[1, exact('host.example')], [3, new Map([[1, '/show/']])]]) }) })),
  requires: 'catu-prefix',
  expected: verified(),
});

// Unverified: time.

vector('expired', 'now equals exp. A token is valid only while now < exp.', {
  url: attach(EPISODE, token()),
  now: MINTED + 300,
  expected: unverified('expired'),
});

vector('not-yet-valid', 'nbf is one second in the future. No clock-skew leeway is allowed.', {
  url: attach(EPISODE, token({ claims: claims({ [NBF]: NOW + 1 }) })),
  expected: unverified('not_yet_valid'),
});

vector('expires-too-far-ahead', 'exp is one second more than 24 hours after the request arrives. The same token verifies a second later.', {
  url: attach(EPISODE, token({ claims: claims({ [EXP]: NOW + WINDOW + 1 }) })),
  expected: unverified('not_yet_valid'),
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

vector('key-not-for-signing', 'Correctly signed by a key the issuer publishes with use "enc". A published key that is not a signing key is treated as absent.', {
  url: attach(EPISODE, token({ key: encKey, kid: ENC_KID })),
  expected: unverified('key_unavailable'),
});

{
  const bytes = Buffer.from(token());
  bytes[bytes.length - 1] ^= 0x01;
  vector('expired-and-badly-signed', 'Two faults at once. It is unverified either way; which reason a verifier reports depends on the order of its checks.', {
    url: attach(EPISODE, bytes),
    now: MINTED + 600,
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

vector('missing-exp', 'A required claim is absent.', {
  url: attach(EPISODE, token({ claims: claims({ [EXP]: undefined }) })),
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
    const [, unprotectedHeader, , signature] = signCose({ protectedHeader: new Map(), payload, privateJwk: signingKey });
    const protectedBytes = encode(new Map([[ALG, -35], [KID, Buffer.from(KEY_ID)]]));
    return encode(new Tagged(18, [protectedBytes, unprotectedHeader, payload, signature]));
  })()),
  expected: unverified('malformed'),
});

vector('kid-in-both-headers', 'kid appears in the protected and the unprotected header.', {
  url: attach(EPISODE, token({ unprotectedExtra: [[KID, Buffer.from(KEY_ID)]] })),
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
