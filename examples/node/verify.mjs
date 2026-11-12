// Verifying a Verified App Attribution token. No dependencies beyond Node (18 or later).
//
//   import { verify } from './verify.mjs';
//
//   const result = verify({ method, url, keysFor });
//   // { verified: true, iss, kid, exp, catu, catm, aud }  or  { verified: false, reason }
//
// `keysFor(iss)` returns the cached JWK Set for an issuer, or null when none is cached. It must
// not fetch: keys are refreshed in the background, never while a request waits.
//
// The result is the document the self-check endpoint returns. What a host does with it is the
// host's policy.
//
// From the command line:
//
//   node verify.mjs <keys.json> <iss> <url> [method] [now]

import { createHash, createPublicKey, verify as verifyBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { decode, encode, Tagged } from './cbor.mjs';
import { ALG, AUD, CATM, CATU, CATV, CTI, EDDSA, ES256, EXP, IAT, ISS, KID, NBF } from './sign.mjs';
import { components, decodeOnce, extractTokens, normalize, origin, split } from './url.mjs';

const CRIT = 2;
const MAX_LIFETIME = 86400;
const ISSUER = /^https:\/\/[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?$/;

class Unverified extends Error {}
const fail = (reason) => {
  throw new Unverified(reason);
};

export function verify({ method = 'GET', url, keysFor, audiencesFor = () => [], now = Math.floor(Date.now() / 1000) }) {
  try {
    return check({ method, url, keysFor, audiencesFor, now });
  } catch (e) {
    if (e instanceof Unverified) return { verified: false, reason: e.message };
    throw e;
  }
}

function check({ method, url, keysFor, audiencesFor, now }) {
  const received = split(url);
  const { tokens, query } = extractTokens(received.query);
  if (tokens.length !== 1) fail('malformed');
  const withoutToken = { ...received, query };

  // 1. Decode.
  const { protectedBytes, protectedHeader, unprotectedHeader, payload, signature } = decodeToken(tokens[0]);
  const alg = protectedHeader.get(ALG);
  if (alg !== ES256 && alg !== EDDSA) fail('malformed');
  if (protectedHeader.has(CRIT)) fail('malformed'); // no extensions are understood
  for (const label of protectedHeader.keys()) if (unprotectedHeader.has(label)) fail('malformed');
  const kidBytes = protectedHeader.get(KID) ?? unprotectedHeader.get(KID);
  if (!(kidBytes instanceof Uint8Array)) fail('malformed');
  const kid = text(kidBytes);
  const claims = decodeMap(payload);

  // 2. Claims.
  const iss = claims.get(ISS);
  const exp = claims.get(EXP);
  const iat = claims.get(IAT);
  const cti = claims.get(CTI);
  if (typeof iss !== 'string' || !ISSUER.test(iss) || iss.endsWith(':443')) fail('malformed');
  if (!Number.isInteger(exp) || !Number.isInteger(iat)) fail('malformed');
  if (!(cti instanceof Uint8Array) || cti.length < 8) fail('malformed');
  if (claims.get(CATV) !== 1) fail('malformed');

  const nbf = claims.get(NBF);
  const aud = claims.get(AUD);
  const catu = claims.get(CATU);
  const catm = claims.get(CATM);
  if (nbf !== undefined && !Number.isInteger(nbf)) fail('malformed');
  if (aud !== undefined && typeof aud !== 'string') fail('malformed');
  if (catu !== undefined && !isUrlRestriction(catu)) fail('malformed');
  if (catm !== undefined && !(Array.isArray(catm) && catm.length && catm.every((m) => typeof m === 'string'))) fail('malformed');

  if (!(iat < exp && exp <= iat + MAX_LIFETIME)) fail('malformed');

  // 3. Time, with no leeway.
  if (!(now < exp)) fail('expired');
  if (nbf !== undefined && !(nbf <= now)) fail('not_yet_valid');

  // 4. The key, looked up only under the token's own issuer.
  const jwk = (keysFor(iss)?.keys ?? []).find((k) => k.kid === kid && usable(k, alg));
  if (!jwk) fail('key_unavailable');

  // 5. Signature.
  const toBeVerified = encode(['Signature1', protectedBytes, Buffer.alloc(0), payload]);
  if (!signatureValid(alg, jwk, toBeVerified, signature)) fail('bad_signature');

  // 6. Restrictions, against the request as received.
  if (catu !== undefined) {
    // Normalized first; then with the path and query exactly as received, for issuers that
    // bind them verbatim. Scheme, host and port are always compared normalized.
    const normalized = normalize(withoutToken);
    const verbatim = { ...normalized, path: withoutToken.path, query: withoutToken.query };
    const matches = (parts) => urlMatches(catu, components(parts));
    if (!matches(normalized) && !matches(verbatim)) fail('url_mismatch');
  }
  if (catm !== undefined && !catm.includes(method)) fail('method_mismatch');
  if (aud !== undefined && aud !== origin(url) && !audiencesFor(iss).includes(aud)) fail('audience_mismatch');

  return {
    verified: true,
    iss,
    kid,
    exp,
    catu: catu === undefined ? null : true,
    catm: catm === undefined ? null : true,
    aud: aud === undefined ? null : true,
  };
}

// base64url (padding optional) → CBOR → COSE_Sign1, untagged, tagged 18, or tagged 61 around 18.
function decodeToken(value) {
  const encoded = decodeOnce(value).replace(/=+$/, '');
  if (!/^[A-Za-z0-9_-]+$/.test(encoded) || encoded.length % 4 === 1) fail('malformed');

  let item = decodeCbor(Buffer.from(encoded, 'base64url'));
  if (item instanceof Tagged && item.tag === 61) item = item.value;
  if (item instanceof Tagged && item.tag === 18) item = item.value;

  if (!Array.isArray(item) || item.length !== 4) fail('malformed');
  const [protectedBytes, unprotectedHeader, payload, signature] = item;
  const bytes = (v) => v instanceof Uint8Array;
  if (!bytes(protectedBytes) || !(unprotectedHeader instanceof Map) || !bytes(payload) || !bytes(signature)) fail('malformed');

  return { protectedBytes, protectedHeader: decodeMap(protectedBytes), unprotectedHeader, payload, signature };
}

function decodeCbor(bytes) {
  try {
    return decode(bytes);
  } catch {
    fail('malformed');
  }
}

function decodeMap(bytes) {
  const map = decodeCbor(bytes);
  if (!(map instanceof Map)) fail('malformed');
  return map;
}

function text(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail('malformed');
  }
}

// A published key that does not fit the token's algorithm is treated as absent.
function usable(jwk, alg) {
  const [kty, crv, name] = alg === ES256 ? ['EC', 'P-256', 'ES256'] : ['OKP', 'Ed25519', 'EdDSA'];
  return (
    jwk.kty === kty &&
    jwk.crv === crv &&
    jwk.use === 'sig' &&
    (jwk.alg === undefined || jwk.alg === name) &&
    (jwk.key_ops === undefined || jwk.key_ops.includes('verify'))
  );
}

function signatureValid(alg, jwk, data, signature) {
  try {
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    if (alg === ES256) {
      return signature.length === 64 && verifyBytes('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, signature);
    }
    return verifyBytes(null, data, key, signature);
  } catch {
    return false;
  }
}

// catu: a map from component label to a map of match type → expected value.
function isUrlRestriction(catu) {
  return catu instanceof Map && [...catu].every(([part, match]) => Number.isInteger(part) && match instanceof Map);
}

function urlMatches(catu, parts) {
  for (const [part, match] of catu) {
    const actual = parts.get(part);
    if (actual === undefined) return false;
    for (const [type, expected] of match) {
      if (!componentMatches(type, expected, actual)) return false;
    }
  }
  return true;
}

// Exact, prefix, suffix, contains and SHA-256. A match type this verifier does not support
// (regular expression, SHA-512/256) fails the match, as CTA-5007-B requires.
function componentMatches(type, expected, actual) {
  if (type === -1) {
    return expected instanceof Uint8Array && createHash('sha256').update(actual).digest().equals(Buffer.from(expected));
  }
  if (typeof expected !== 'string') return false;
  if (type === 0) return actual === expected;
  if (type === 1) return actual.startsWith(expected);
  if (type === 2) return actual.endsWith(expected);
  if (type === 3) return actual.includes(expected);
  return false;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [keysFile, iss, url, method = 'GET', now] = process.argv.slice(2);
  if (!url) {
    console.error('usage: node verify.mjs <keys.json> <iss> <url> [method] [now]');
    process.exit(2);
  }
  const keys = JSON.parse(readFileSync(keysFile, 'utf8'));
  const result = verify({
    method,
    url,
    keysFor: (issuer) => (issuer === iss ? keys : null),
    ...(now ? { now: Number(now) } : {}),
  });
  console.log(JSON.stringify(result, null, 2));
  process.exit(result.verified ? 0 : 1);
}
