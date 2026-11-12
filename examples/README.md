# Examples

Two small implementations of both sides: minting a token (what an application does) and verifying one (what a host does). Both pass every [test vector](../test-vectors/), and each verifies tokens minted by the other.

They are written to be read. Neither fetches or caches keys; a real host does that in the background, as the [specification](../SPEC.md#publishing-keys) describes.

## Node

No dependencies. Node 18 or later. Every byte of the encoding is visible, which makes it the one to read alongside the specification.

| File | What |
|---|---|
| [`node/sign.mjs`](node/sign.mjs) | `mint()`: a per-request or session token. About 40 lines of substance. |
| [`node/verify.mjs`](node/verify.mjs) | `verify()`: the six verification steps, in order. Returns the self-check document. |
| [`node/url.mjs`](node/url.mjs) | Attaching and finding the `CAT` parameter, URL normalization, `catu` components. |
| [`node/cbor.mjs`](node/cbor.mjs) | A strict, deterministic CBOR encoder and decoder for the handful of types a token uses. |

```sh
# Mint a per-request token with the sample key and print the URL to request
node examples/node/sign.mjs test-vectors/private-keys.json 2026-11 https://exampleplayer.com \
  'https://host.example/show/episode.mp3?id=42'

# Verify a request URL against a key set
node examples/node/verify.mjs test-vectors/keys.json https://exampleplayer.com '<url>'

# Run the test vectors
node examples/node/run-vectors.mjs
```

## Python

The same thing with libraries: [`cbor2`](https://pypi.org/project/cbor2/) for CBOR and [`cryptography`](https://pypi.org/project/cryptography/) for signatures. Python 3.10 or later.

| File | What |
|---|---|
| [`python/attribution.py`](python/attribution.py) | `mint()`, `attach()` and `verify()`. |

```sh
uv run examples/python/run_vectors.py
# or: pip install cbor2 cryptography && python examples/python/run_vectors.py
```

`mint()` here signs with ES256 only; `verify()` accepts ES256 and EdDSA.

## Notes for implementers

- **ES256 signatures are 64 bytes**, `r` then `s`. Most crypto libraries produce and expect DER by default; convert, or ask for the raw form (`dsaEncoding: 'ieee-p1363'` in Node).
- **Verify over the protected header bytes as received.** Do not decode and re-encode them.
- **General-purpose CBOR decoders are lenient.** Many accept trailing data and duplicate map keys, which the specification requires a host to reject. The Python example shows one way to make a lenient decoder strict.
- **Check types exactly.** In several languages `true == 1`; a claim of `true` is not `catv: 1`.
- **Handle the request URL as a string.** URL classes normalize as they parse, and the as-received path and query matter for `catu`.
- **`catu` match types.** Both examples support exact, prefix, suffix, contains and SHA-256. Regular-expression and SHA-512/256 matches are reported as `url_mismatch`.

Code here is MIT licensed (see [LICENSE](LICENSE)).
