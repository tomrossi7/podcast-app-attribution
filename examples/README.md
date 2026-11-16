# Examples

Start with Node. It is the reference implementation: it mints and verifies, has no dependencies, and generates the test vectors. The other languages are optional and are here for people who work in them.

## Getting started

Node 18 or later, nothing to install. From the repository root:

```sh
# Mint a token with the sample key and print the URL to request
node examples/node/sign.mjs test-vectors/private-keys.json 2026-11 https://exampleplayer.com \
  'https://host.example/show/episode.mp3?id=42'

# Verify that URL against the sample key set
node examples/node/verify.mjs test-vectors/keys.json https://exampleplayer.com '<the URL printed above>'
```

The second command prints the result:

```json
{ "verified": true, "iss": "https://exampleplayer.com" }
```

Change a character of the path and run it again: `{ "verified": false, "reason": "url_mismatch" }`.

Then run the [test vectors](../test-vectors/):

```sh
node examples/node/run-vectors.mjs
```

## What is here

| | Mint (application side) | Verify (host side) | |
|---|---|---|---|
| [Node](#node) | ✓ | ✓ | Reference implementation |
| [Ruby](#ruby) | ✓ | ✓ | Optional |
| [Python](#python) | ✓ | ✓ | Optional |
| [Swift](#swift-and-kotlin) | ✓ | | Optional, demonstration |
| [Kotlin](#swift-and-kotlin) | ✓ | | Optional, demonstration |

Every verifier passes every test vector, and tokens minted by each example verify with the others.

None of them fetches or caches keys; a real host does that in the background, as the [specification](../SPEC.md#publishing-keys) describes.

## Node

No dependencies. Node 18 or later. Every byte of the encoding is visible, which makes it the one to read alongside the specification.

| File | What |
|---|---|
| [`node/sign.mjs`](node/sign.mjs) | `mint()`: a per-request or session token. About 40 lines of substance. |
| [`node/verify.mjs`](node/verify.mjs) | `verify()`: the six verification checks. Returns the self-check document. |
| [`node/url.mjs`](node/url.mjs) | Attaching and finding the `CAT` parameter, URL normalization, `catu` components. |
| [`node/cbor.mjs`](node/cbor.mjs) | A strict, deterministic CBOR encoder and decoder for the handful of types a token uses. |

## Ruby

Standard library only (`openssl`). Ruby 3.1 or later.

| File | What |
|---|---|
| [`ruby/attribution.rb`](ruby/attribution.rb) | `Attribution.mint`, `.attach` and `.verify`, including building OpenSSL keys from JWKs. |
| [`ruby/cbor.rb`](ruby/cbor.rb) | The same strict CBOR subset as the Node example. |

```sh
ruby examples/ruby/run_vectors.rb
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

## Swift and Kotlin

These show how a token is built and signed in the languages mobile apps are written in. They sign with ES256 and take the key as a parameter.

**They are demonstrations, not a production design.** A signing key shipped inside an app can be extracted, and then anyone can sign as that app. Minting tokens on a server you control and handing them to the app avoids that, and the app-side code shrinks to appending the token to the URL. Neither arrangement is required; [Protecting the key](../SPEC.md#protecting-the-key) sets out the trade-offs.

### Swift

For iOS and macOS apps. CryptoKit only, in a single file: [`Attribution.swift`](swift/Sources/Attribution/Attribution.swift).

```swift
let token = try Attribution.mint(key: key, kid: "2026-11", iss: "https://exampleplayer.com", url: url)
let asset = AVURLAsset(url: URL(string: Attribution.attach(token, to: url))!)
```

The package around it exists so the example can be built and run from the command line, including on Linux, where [swift-crypto](https://github.com/apple/swift-crypto) stands in for CryptoKit:

```sh
cd examples/swift
swift run mint ../../test-vectors/private-keys.json 2026-11 https://exampleplayer.com \
  'https://host.example/show/episode.mp3?id=42'
```

### Kotlin

For Android (API 26 or later) and the JVM. JDK classes only, in a single file: [`Attribution.kt`](kotlin/Attribution.kt).

```kotlin
val token = Attribution.mint(key, kid = "2026-11", iss = "https://exampleplayer.com", url = url)
val request = Request.Builder().url(Attribution.attach(url, token)).build()
```

```sh
cd examples/kotlin
kotlinc Attribution.kt Main.kt -include-runtime -d attribution.jar
java -jar attribution.jar ../../test-vectors/private-keys.json 2026-11 https://exampleplayer.com \
  'https://host.example/show/episode.mp3?id=42'
```

## Notes for implementers

- **ES256 signatures are 64 bytes**, `r` then `s`. Most crypto libraries produce and expect DER by default; convert (as the Kotlin and Ruby examples do), or ask for the raw form (`dsaEncoding: 'ieee-p1363'` in Node, `rawRepresentation` in CryptoKit).
- **Verify over the protected header bytes as received.** Do not decode and re-encode them.
- **General-purpose CBOR decoders are lenient.** Many accept trailing data and duplicate map keys, which the specification requires a host to reject. The Python example shows one way to make a lenient decoder strict.
- **Check types exactly.** In several languages `true == 1`; a claim of `true` is not `catv: 1`.
- **Handle the request URL as a string.** URL classes normalize as they parse, and the as-received path and query matter for `catu`.
- **`catu` match types.** Exact match is the one every host supports. The examples also handle prefix, suffix, contains and SHA-256; regular-expression and SHA-512/256 matches are reported as `url_mismatch`.

Code here is MIT licensed (see [LICENSE](LICENSE)).
