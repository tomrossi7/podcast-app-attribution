// Minting a Verified App Attribution token. No dependencies beyond Node (18 or later).
//
//   import { mint } from './sign.mjs';
//   import { attach } from './url.mjs';
//
//   const token = mint({ privateJwk, kid: '2026-11', iss: 'https://exampleplayer.com', url });
//   fetch(attach(url, token));
//
// Leave `url` out for a session token that can be attached to any request until it expires.
//
// From the command line:
//
//   node sign.mjs <private-keys.json> <kid> <iss> [url]
//
// The key file holds one private JWK, or a JWK Set from which the key named by kid is taken.

import { createPrivateKey, sign as signBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { encode, Tagged } from './cbor.mjs';
import { attach, extractTokens, normalize, split } from './url.mjs';

// CWT and CAT claim labels (IANA CWT Claims registry).
export const ISS = 1, AUD = 3, EXP = 4, NBF = 5, IAT = 6, CTI = 7, CATV = 310, CATU = 312, CATM = 313;
// COSE header labels and the ES256 algorithm value.
export const ALG = 1, KID = 4, ES256 = -7;

export function mint({ privateJwk, kid, iss, url, methods = ['GET', 'HEAD'], aud, lifetime = 300, now = unixTime() }) {
  const claims = new Map([
    [ISS, iss],
    [EXP, now + lifetime],
    [CATV, 1],
  ]);
  if (aud) claims.set(AUD, aud);
  if (url) {
    claims.set(CATU, exactUrl(url));
    claims.set(CATM, methods);
  }
  const protectedHeader = new Map([
    [ALG, ES256],
    [KID, Buffer.from(kid, 'utf8')],
  ]);
  return toBase64Url(encode(new Tagged(18, signCose({ protectedHeader, payload: encode(claims), privateJwk }))));
}

// A catu that matches exactly this URL: scheme, host, path and query, after removing any CAT
// parameter and normalizing. Port is left out, so any port matches.
export function exactUrl(url) {
  const parts = split(url);
  const n = normalize({ ...parts, query: extractTokens(parts.query).query });
  const exact = (value) => new Map([[0, value]]);
  return new Map([
    [0, exact(n.scheme)],
    [1, exact(n.host)],
    [3, exact(n.path)],
    [4, exact(n.query ?? '')],
  ]);
}

// COSE_Sign1 (RFC 9052 §4.2): [protected header as bytes, unprotected header, payload, signature].
// The signature covers the Sig_structure of §4.4 with empty external data.
export function signCose({ protectedHeader, unprotectedHeader = new Map(), payload, privateJwk }) {
  const protectedBytes = encode(protectedHeader);
  const toBeSigned = encode(['Signature1', protectedBytes, Buffer.alloc(0), payload]);
  if (privateJwk.kty !== 'EC' || privateJwk.crv !== 'P-256') throw new Error('ES256 needs a P-256 key');
  const key = createPrivateKey({ key: privateJwk, format: 'jwk' });
  const signature = signBytes('sha256', toBeSigned, { key, dsaEncoding: 'ieee-p1363' }); // 64 bytes, r then s
  return [protectedBytes, unprotectedHeader, payload, signature];
}

export function toBase64Url(bytes) {
  return Buffer.from(bytes).toString('base64url');
}

function unixTime() {
  return Math.floor(Date.now() / 1000);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [keyFile, kid, iss, url] = process.argv.slice(2);
  if (!iss) {
    console.error('usage: node sign.mjs <private-keys.json> <kid> <iss> [url]');
    process.exit(2);
  }
  const file = JSON.parse(readFileSync(keyFile, 'utf8'));
  const privateJwk = file.keys ? file.keys.find((k) => k.kid === kid) : file;
  const token = mint({ privateJwk, kid, iss, url });
  console.log(url ? attach(url, token) : token);
}
