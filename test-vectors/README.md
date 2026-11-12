# Test vectors

Requests carrying tokens, and what a conforming verifier reports for each. Run your implementation against them before trusting it.

| File | What |
|---|---|
| [`vectors.json`](vectors.json) | The vectors. |
| [`keys.json`](keys.json) | The JWK Set the sample issuer `https://exampleplayer.com` publishes: an ES256 key (`2026-11`) and an Ed25519 key (`2026-11-ed`). |
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
      "expected": { "verified": true, "iss": "https://exampleplayer.com", "kid": "2026-11", "exp": 1800000300, "catu": true, "catm": true, "aud": null },
      "diagnostic": "18([<< {1: -7, 4: h'…'} >>, {}, << {1: \"https://exampleplayer.com\", …} >>, h'…'])"
    }
  ]
}
```

For each vector, verify the request (`method` and `url`, exactly as given) as if the current time were `now`, with this host state:

- The key set in `keys.json` is cached for `issuer`. No other issuer has cached keys, and nothing may be fetched.
- `accepted_audiences`, when the vector has it, lists the `aud` values the host has configured for the issuer in addition to its own origin. Otherwise there are none.

The result must equal `expected`, which is the document the [self-check endpoint](../SPEC.md#self-check) returns.

`requires: "EdDSA"` marks a vector for hosts that support the optional algorithm. A host that does not support it reports `{"verified": false, "reason": "malformed"}` for that vector.

`diagnostic` is the token in CBOR diagnostic notation, for reading. `<< … >>` is a byte string whose content is itself CBOR; `h'…'` is a byte string in hex. It is `null` where the token does not decode.

## What they cover

- **Verified:** per-request and session tokens; the 24-hour lifetime boundary; `kid` in either header; untagged, tag 18, and tag 61 around 18; padded base64url; `aud` as the request origin and as a configured value; `catu` with exact and prefix matches, against a URL that needs normalizing and against one bound verbatim; EdDSA.
- **Time:** expired at exactly `exp`; `nbf` one second ahead; a lifetime over 24 hours.
- **Keys and signature:** a flipped signature bit; the wrong key under the right `kid`; an unknown `kid`; an unknown issuer; a `kid` naming a key of the wrong type; and the order of checks when a token is both expired and badly signed.
- **Restrictions:** the wrong URL; port `"443"` (which never matches); the wrong method; the wrong audience.
- **Malformed:** missing and short `cti`; an unsupported `catv`; an `iss` that is not a bare HTTPS origin; an unsupported `alg`; `kid` in both headers; an unknown `crit` entry; a duplicated claim under a valid signature; trailing data; a value that is not base64url; two `CAT` parameters.

The vectors check behavior the specification requires. They do not include tokens that are merely non-deterministically encoded, which a host SHOULD, but need not, reject.
