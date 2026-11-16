# Verified App Attribution

**DKIM for podcast apps.** An app publishes a public key on its own domain and signs its episode requests. A host checks the signature and learns which domain issued it, instead of trusting a User-Agent string. No registry, no approval.

## The problem

A podcast host works out which app made a request by reading its `User-Agent` header. That header is whatever the sender chooses to type:

- Anyone can copy it, so a script can show up as a popular app.
- Many apps arrive as the name of their HTTP library (`okhttp`, `Dalvik`, `CFNetwork`) and can't be told apart.
- Hosts match it against hand-kept lists, so a new or small app is "Other" until somebody adds it.

An app has no way to stand behind its own traffic, and a host has no way to tell an app from an imitation of it. Smaller apps feel this most. They are the ones missing from the lists, and nothing they send carries more weight than what an imitator sends.

## The idea

Email had the same problem with the `From` line. DKIM answered it: a domain publishes a public key, signs what it sends, and receivers check the signature against that key.

This does the same for podcast apps. The app's domain is its identity. It publishes a key there, signs a short-lived token, and adds the token to the episode URL. Any host can check the token against the published key and attribute the request to that domain.

Three principles:

- **A non-blocking trust signal for podcast applications.** It is meant to add information to a request, not to gate it. That describes what the signal is for. It does not restrict a host, which decides for itself what to do with signed, unsigned and failed requests.
- **The domain is the identity.** Anyone can verify as themselves without asking permission. Publish a key on your domain and you are verifiable as that domain.
- **Verified means attributable, not necessarily countable.** A valid token ties a request to an issuer domain. It does not say that a person listened.

## An example

ExamplePlayer is a podcast app whose website is `exampleplayer.com`.

**1. It publishes a public key** in a small JSON file on its own site:

```
https://exampleplayer.com/.well-known/podcast-app-keys.json
```

```json
{ "keys": [ { "kid": "2026-11", "kty": "EC", "crv": "P-256", "use": "sig", "x": "…", "y": "…" } ] }
```

**2. It signs a short-lived token** with the matching private key. In plain terms the token says:

```
issued by   https://exampleplayer.com
expires     in 5 minutes
good for    GET https://host.example/show/episode.mp3
signed with key 2026-11
```

**3. It appends the token to the episode URL** as one extra query parameter:

```
https://host.example/show/episode.mp3?CAT=0oRMogEmBEcyMDI2LTEx…
```

**4. The host verifies it.** The host checks the signature against ExamplePlayer's key file, and checks the expiry and the URL. The result is a verified issuer:

```
verified issuer: https://exampleplayer.com
```

A request with no token, or with one that fails, is simply unverified. So are the first requests from an app the host has never seen: the host fetches the key file in the background, not while a listener waits, and verifies the requests that come after.

To run those four steps yourself with the sample keys in this repository (Node 18 or later, nothing to install):

```sh
# Steps 2 and 3: sign a token and print the URL to request
node examples/node/sign.mjs test-vectors/private-keys.json 2026-11 https://exampleplayer.com \
  'https://host.example/show/episode.mp3'

# Step 4: verify that URL against the published keys
node examples/node/verify.mjs test-vectors/keys.json https://exampleplayer.com '<the URL printed above>'
```

The details an implementer needs (how the token is encoded, which fields it carries, the exact verification steps) are in the [specification](SPEC.md).

## What verification tells a host, and what it doesn't

A verified request carries a valid, unexpired token issued under the key that the domain publishes. That is a much stronger statement than a User-Agent, and it is all the statement there is.

- **It does not show that the app itself sent this request.** A token can be copied and replayed until it expires. Tokens that last a few minutes and are bound to one URL narrow that risk; they do not remove it.
- **It does not show that a person listened.**
- **It says nothing about the listener.** Tokens carry no listener or device identifiers.
- **It is only as strong as the app's control of its signing key.** A key shipped inside an app can be extracted. The specification describes [the trade-offs](SPEC.md#protecting-the-key) without requiring any one arrangement.

## What stays true

- No central registry and no approval process.
- Identity and key discovery are controlled by the app's own domain.
- No listener or device identity.
- Participation is optional, for apps and for hosts.
- Attribution is verifiable independently of the User-Agent.
- Policy belongs to the host. The specification defines the signal and how to verify it, and stops there.

## Known limits

This is an experiment, and some of real-world podcast delivery is unresolved: redirects through tracking prefixes, CDNs that cache by query string, enclosure URLs that are already signed, tokens appearing in logs, and long playback sessions that outlive a token. The specification [says where each stands](SPEC.md#deployment-considerations).

## Status

Draft 0.1, experimental. The spec is written to gather implementation experience before consideration by the Podcast Standards Project or another standards body. Expect it to change. Questions and objections are welcome in [Discussions](../../discussions); concrete problems with the text in [Issues](../../issues).

## In this repository

| Path | What |
|---|---|
| [`SPEC.md`](SPEC.md) | The specification: the token, key publishing, and verification. |
| [`examples/`](examples/) | A reference implementation in Node, and optional examples in other languages. |
| [`test-vectors/`](test-vectors/) | Sample keys and requests, with the result a verifier should report for each. |

The token is a [Common Access Token](https://shop.cta.tech/products/common-access-token-cta-5007-b) (CTA-5007-B), the streaming industry's token format, used here as a signal rather than a gate.

## License

The specification text is licensed under [CC BY 4.0](LICENSE). Example code is MIT.
