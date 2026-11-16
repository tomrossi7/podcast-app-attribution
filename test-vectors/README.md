# Test vectors

Requests carrying tokens, and what a conforming verifier reports for each.

## Start with these five

If you are writing a verifier, get these right first. Each is one entry in [`vectors.json`](vectors.json), found by its `name`.

| Case | Vector | A verifier reports |
|---|---|---|
| A valid token | `per-request` | verified, issuer `https://exampleplayer.com` |
| An expired token | `expired` | unverified: `expired` |
| An invalid signature | `bad-signature` | unverified: `bad_signature` |
| The wrong URL | `url-mismatch` | unverified: `url_mismatch` |
| An unknown issuer or key | `unknown-issuer`, `unknown-kid` | unverified: `key_unavailable` |

To see them run against the reference implementation:

```sh
node examples/node/run-vectors.mjs per-request expired bad-signature url-mismatch unknown-issuer unknown-kid
```

## The full suite

The other vectors are an interoperability resource for an implementation that is past those five: the encodings a verifier has to accept, the boundaries, and the malformed tokens it has to reject. Run all of them before trusting a verifier with real traffic.

```sh
node examples/node/run-vectors.mjs
```

| File | What |
|---|---|
| [`vectors.json`](vectors.json) | The vectors. |
| [`keys.json`](keys.json) | The JWK Set the sample issuer `https://exampleplayer.com` publishes: its signing key (`2026-11`) and a key that is not for signing (`2026-11-enc`), which a verifier has to ignore. |
| [`private-keys.json`](private-keys.json) | The matching private keys, so you can mint your own tokens against the same key set. **Sample keys, public on purpose. Never use them for anything real.** |
| [`generate.mjs`](generate.mjs) | Regenerates `vectors.json`. Signatures are randomized, so the tokens change on every run; the expected results do not. |

## Format

```json
{
  "issuer": "https://exampleplayer.com",
  "keys": "keys.json",
  "vectors": [
    {
      "name": "per-request",
      "description": "…",
      "method": "GET",
      "url": "https://host.example/show/episode.mp3?id=42&CAT=…",
      "now": 1800000060,
      "expected": { "verified": true, "iss": "https://exampleplayer.com" },
      "diagnostic": "18([<< {1: -7, 4: h'…'} >>, {}, << {1: \"https://exampleplayer.com\", …} >>, h'…'])"
    }
  ]
}
```

For each vector, verify the request (`method` and `url`, exactly as given) as if the current time were `now`, with this host state:

- The key set in `keys.json` is cached for `issuer`. No other issuer has cached keys, and nothing may be fetched.
- `accepted_audiences`, when the vector has it, lists the `aud` values the host has configured for the issuer in addition to its own origin. Otherwise there are none.

`expected` is the document the [self-check endpoint](../SPEC.md#self-check) returns. A verifier has to match `verified` and, when verified, `iss`. An unverified vector also gives a `reason`. Reasons are diagnostic, so matching it is useful and not required: for a token with more than one fault, another reason is just as correct.

`requires` marks a vector that uses something optional for hosts. The only one is `"catu-prefix"`, a `catu` prefix match. A verifier that does not support it reports that request as unverified.

`diagnostic` is the token in CBOR diagnostic notation, for reading. `<< … >>` is a byte string whose content is itself CBOR; `h'…'` is a byte string in hex. It is `null` where the token does not decode.

## What they cover

- **Verified:** per-request and session tokens; an `exp` exactly 24 hours ahead; the optional `iat` and `cti` claims; `kid` in either header; untagged, tag 18, and tag 61 around 18; padded base64url; `aud` as the request origin and as a configured value; `catu` with exact and prefix matches, against a URL that needs normalizing and against one bound verbatim.
- **Time:** expired at exactly `exp`; `nbf` one second ahead; an `exp` more than 24 hours ahead.
- **Keys and signature:** a flipped signature bit; the wrong key under the right `kid`; an unknown `kid`; an unknown issuer; a published key that is not for signing; and a token that is both expired and badly signed.
- **Restrictions:** the wrong URL; port `"443"` (which never matches); the wrong method; the wrong audience.
- **Malformed:** a missing `exp`; an unsupported `catv`; an `iss` that is not a bare HTTPS origin; an unsupported `alg`; `kid` in both headers; an unknown `crit` entry; a duplicated claim under a valid signature; trailing data; a value that is not base64url; two `CAT` parameters.

The vectors check behavior the specification requires. They do not include tokens that are merely non-deterministically encoded, which a host SHOULD, but need not, reject.
