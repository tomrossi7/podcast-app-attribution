# Verified App Attribution

A way for a podcast application to attach a verifiable attribution credential to its episode requests, so the host can attribute them to the application's domain with confidence.

The application signs a short-lived token with a key it publishes on its own domain and appends it to the media URL as `?CAT=…`. The host verifies the signature against that published key. That's the whole protocol.

- **Non-blocking.** It's a trust signal. What a host does with it is the host's policy.
- **The domain is the identity.** Publish a key at `/.well-known/podcast-app-keys.json` and you're verified as yourself. No registry, no approval.
- **Verified means attributable, not necessarily countable.** A valid token attributes the request to a verified issuer domain, not to a listen.

The token is a [Common Access Token](https://shop.cta.tech/products/common-access-token-cta-5007-b) (CTA-5007-B), the streaming industry's token format, used here as a signal rather than a gate.

No central authority is involved. Owning a domain (DNS and TLS) is the root of identity, and CAT/CWT supplies the signed credential, so the whole thing stays open: any application can participate by publishing a key, and any host by verifying one.

**[Read the specification →](SPEC.md)**

## Status

Draft 0.1, experimental. The spec is written to gather implementation experience before consideration by the Podcast Standards Project or another standards body. Expect it to change. Questions and objections are welcome in [Discussions](../../discussions); concrete problems with the text in [Issues](../../issues).

## In this repository

| Path | What |
|---|---|
| [`SPEC.md`](SPEC.md) | The specification. |
| [`test-vectors/`](test-vectors/) | Sample keys, 37 requests carrying tokens, and what a conforming verifier reports for each. |
| [`examples/`](examples/) | Minting in Swift and Kotlin; minting and verifying in Node, Ruby and Python. Every verifier passes every test vector. |

## License

The specification text is licensed under [CC BY 4.0](LICENSE). Example code is MIT.
