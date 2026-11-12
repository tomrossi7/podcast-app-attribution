"""Minting and verifying Verified App Attribution tokens with cbor2 and cryptography.

    token = mint(private_jwk, kid="2026-11", iss="https://exampleplayer.com", url=url)
    requests.get(attach(url, token))

    result = verify(url, keys_for=cached_key_set)
    # {"verified": True, "iss": ..., "kid": ..., "exp": ..., "catu": ..., "catm": ..., "aud": ...}
    # or {"verified": False, "reason": ...}

`keys_for(iss)` returns the cached JWK Set for an issuer, or None when none is cached. It must not
fetch: keys are refreshed in the background, never while a request waits.
"""

import base64
import hashlib
import os
import re
import time
from collections.abc import Mapping
from urllib.parse import unquote

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

# CWT and CAT claim labels (IANA CWT Claims registry).
ISS, AUD, EXP, NBF, IAT, CTI, CATV, CATU, CATM = 1, 3, 4, 5, 6, 7, 310, 312, 313
# COSE header labels and algorithm values.
ALG, CRIT, KID, ES256, EDDSA = 1, 2, 4, -7, -8

MAX_LIFETIME = 86400
ISSUER = re.compile(r"https://[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?")


# --- minting ------------------------------------------------------------------------------------


def mint(private_jwk, kid, iss, url=None, methods=("GET", "HEAD"), aud=None, lifetime=300, now=None):
    """A per-request token when `url` is given, otherwise a session token."""
    now = int(time.time()) if now is None else now
    claims = {ISS: iss, EXP: now + lifetime, IAT: now, CTI: os.urandom(16), CATV: 1}
    if aud:
        claims[AUD] = aud
    if url:
        claims[CATU] = exact_url(url)
        claims[CATM] = list(methods)

    # COSE_Sign1 (RFC 9052 §4.2): [protected header as bytes, unprotected header, payload, signature].
    protected = cbor2.dumps({ALG: ES256, KID: kid.encode()})
    payload = cbor2.dumps(claims)
    signature = _private_key(private_jwk).sign(_to_be_signed(protected, payload), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(signature)  # DER → the 64-byte r ‖ s form COSE uses
    token = cbor2.CBORTag(18, [protected, {}, payload, r.to_bytes(32, "big") + s.to_bytes(32, "big")])
    return base64.urlsafe_b64encode(cbor2.dumps(token)).rstrip(b"=").decode()


def exact_url(url):
    """A catu matching exactly this URL's scheme, host, path and query. Port is left out."""
    parts = split(url)
    parts["query"] = extract_tokens(parts["query"])[1]
    n = normalize(parts)
    return {0: {0: n["scheme"]}, 1: {0: n["host"]}, 3: {0: n["path"]}, 4: {0: n["query"] or ""}}


def attach(url, token):
    """Appends the token, leaving the URL alone if it already carries one."""
    query = split(url)["query"]
    if extract_tokens(query)[0]:
        return url
    return f"{url}{'?' if query is None else '&'}CAT={token}"


# --- verifying ----------------------------------------------------------------------------------


class Unverified(Exception):
    pass


def verify(url, keys_for, method="GET", audiences_for=lambda iss: (), now=None):
    try:
        return _check(url, keys_for, method, audiences_for, int(time.time()) if now is None else now)
    except Unverified as e:
        return {"verified": False, "reason": str(e)}


def _check(url, keys_for, method, audiences_for, now):
    received = split(url)
    tokens, query = extract_tokens(received["query"])
    if len(tokens) != 1:
        raise Unverified("malformed")
    without_token = {**received, "query": query}

    # 1. Decode.
    protected_bytes, protected, unprotected, payload, signature = _decode_token(tokens[0])
    alg = protected.get(ALG)
    if alg not in (ES256, EDDSA) or CRIT in protected or protected.keys() & unprotected.keys():
        raise Unverified("malformed")
    kid = protected.get(KID, unprotected.get(KID))
    if type(kid) is not bytes:
        raise Unverified("malformed")
    try:
        kid = kid.decode()
    except UnicodeDecodeError:
        raise Unverified("malformed")
    claims = _decode_map(payload)

    # 2. Claims.
    iss, exp, iat, cti = claims.get(ISS), claims.get(EXP), claims.get(IAT), claims.get(CTI)
    nbf, aud, catu, catm = claims.get(NBF), claims.get(AUD), claims.get(CATU), claims.get(CATM)
    well_formed = (
        type(iss) is str
        and ISSUER.fullmatch(iss)
        and not iss.endswith(":443")
        and type(exp) is int
        and type(iat) is int
        and type(cti) is bytes
        and len(cti) >= 8
        and type(claims.get(CATV)) is int
        and claims[CATV] == 1
        and (nbf is None or type(nbf) is int)
        and (aud is None or type(aud) is str)
        and (catu is None or _is_url_restriction(catu))
        and (catm is None or (_is_array(catm) and catm and all(type(m) is str for m in catm)))
        and iat < exp <= iat + MAX_LIFETIME
    )
    if not well_formed:
        raise Unverified("malformed")

    # 3. Time, with no leeway.
    if not now < exp:
        raise Unverified("expired")
    if nbf is not None and not nbf <= now:
        raise Unverified("not_yet_valid")

    # 4. The key, looked up only under the token's own issuer.
    key_set = keys_for(iss) or {"keys": []}
    jwk = next((k for k in key_set["keys"] if k.get("kid") == kid and _usable(k, alg)), None)
    if jwk is None:
        raise Unverified("key_unavailable")

    # 5. Signature.
    if not _signature_valid(alg, jwk, _to_be_signed(protected_bytes, payload), signature):
        raise Unverified("bad_signature")

    # 6. Restrictions, against the request as received.
    if catu is not None:
        # Normalized first; then with the path and query exactly as received, for issuers that
        # bind them verbatim. Scheme, host and port are always compared normalized.
        normalized = normalize(without_token)
        verbatim = {**normalized, "path": without_token["path"], "query": without_token["query"]}
        if not _url_matches(catu, components(normalized)) and not _url_matches(catu, components(verbatim)):
            raise Unverified("url_mismatch")
    if catm is not None and method not in catm:
        raise Unverified("method_mismatch")
    if aud is not None and aud != origin(url) and aud not in audiences_for(iss):
        raise Unverified("audience_mismatch")

    restriction = lambda claim: None if claim is None else True
    return {
        "verified": True,
        "iss": iss,
        "kid": kid,
        "exp": exp,
        "catu": restriction(catu),
        "catm": restriction(catm),
        "aud": restriction(aud),
    }


def _decode_token(value):
    """base64url (padding optional) → CBOR → COSE_Sign1, untagged, tagged 18, or 61 around 18."""
    encoded = unquote(value).rstrip("=")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", encoded) or len(encoded) % 4 == 1:
        raise Unverified("malformed")
    item = _decode_cbor(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
    if isinstance(item, cbor2.CBORTag) and item.tag == 61:
        item = item.value
    if isinstance(item, cbor2.CBORTag) and item.tag == 18:
        item = item.value
    if not _is_array(item) or len(item) != 4:
        raise Unverified("malformed")
    protected_bytes, unprotected, payload, signature = item
    if not (type(protected_bytes) is bytes and _is_map(unprotected) and type(payload) is bytes and type(signature) is bytes):
        raise Unverified("malformed")
    return protected_bytes, _decode_map(protected_bytes), unprotected, payload, signature


def _decode_cbor(data):
    """Decodes one item, strictly.

    cbor2 is lenient: it accepts trailing data, duplicate map keys (the last one wins) and
    encodings that are not deterministic. Encoding the result again and comparing it with the
    input catches all three, because cbor2 encodes deterministically and keeps map order.
    """
    try:
        item = cbor2.loads(data)
        if cbor2.dumps(item) != data:
            raise ValueError("not deterministically encoded")
    except Exception:
        raise Unverified("malformed")
    return item


def _decode_map(data):
    item = _decode_cbor(data)
    if not _is_map(item):
        raise Unverified("malformed")
    return item


# cbor2 returns its own immutable map and array types for some nested values, so test by kind.
def _is_map(value):
    return isinstance(value, Mapping)


def _is_array(value):
    return isinstance(value, (list, tuple))


def _to_be_signed(protected_bytes, payload):
    # Sig_structure (RFC 9052 §4.4) with empty external data.
    return cbor2.dumps(["Signature1", protected_bytes, b"", payload])


def _usable(jwk, alg):
    """A published key that does not fit the token's algorithm is treated as absent."""
    kty, crv, name = ("EC", "P-256", "ES256") if alg == ES256 else ("OKP", "Ed25519", "EdDSA")
    return (
        jwk.get("kty") == kty
        and jwk.get("crv") == crv
        and jwk.get("use") == "sig"
        and jwk.get("alg", name) == name
        and "verify" in jwk.get("key_ops", ["verify"])
    )


def _signature_valid(alg, jwk, data, signature):
    try:
        if alg == ES256:
            if len(signature) != 64:
                return False
            numbers = ec.EllipticCurvePublicNumbers(_b64int(jwk["x"]), _b64int(jwk["y"]), ec.SECP256R1())
            der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
            numbers.public_key().verify(der, data, ec.ECDSA(hashes.SHA256()))
        else:
            ed25519.Ed25519PublicKey.from_public_bytes(_b64(jwk["x"])).verify(signature, data)
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


def _private_key(jwk):
    return ec.derive_private_key(_b64int(jwk["d"]), ec.SECP256R1())


def _b64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _b64int(value):
    return int.from_bytes(_b64(value), "big")


def _is_url_restriction(catu):
    return _is_map(catu) and all(type(part) is int and _is_map(match) for part, match in catu.items())


def _url_matches(catu, parts):
    return all(
        part in parts and all(_component_matches(kind, expected, parts[part]) for kind, expected in match.items())
        for part, match in catu.items()
    )


def _component_matches(kind, expected, actual):
    """Exact, prefix, suffix, contains and SHA-256. Unsupported match types fail the match."""
    if kind == -1:
        return type(expected) is bytes and hashlib.sha256(actual.encode()).digest() == expected
    if type(expected) is not str:
        return False
    if kind == 0:
        return actual == expected
    if kind == 1:
        return actual.startswith(expected)
    if kind == 2:
        return actual.endswith(expected)
    if kind == 3:
        return expected in actual
    return False


# --- URLs ---------------------------------------------------------------------------------------
# Handled as strings on purpose: a general-purpose URL parser rewrites what it parses, and "the
# URL as received" matters here.


def split(url):
    """RFC 3986 Appendix B, plus the authority split into host and port."""
    m = re.match(r"(?:([^:/?#]+):)?(?://([^/?#]*))?([^?#]*)(?:\?([^#]*))?", url)
    authority = re.sub(r"^.*@", "", m.group(2) or "")
    host, port = re.fullmatch(r"(\[[^\]]*\]|[^:]*)(?::(.*))?", authority).groups()
    return {"scheme": m.group(1) or "", "host": host, "port": port or "", "path": m.group(3), "query": m.group(4)}


def extract_tokens(query):
    """The values of the CAT parameters in a query, and the query without them."""
    if query is None:
        return [], None
    tokens, rest = [], []
    for field in query.split("&"):
        name, eq, value = field.partition("=")
        if unquote(name) == "CAT":
            tokens.append(value)
        else:
            rest.append(field)
    return tokens, "&".join(rest) if rest else None


def normalize(parts):
    """RFC 9110 §4.2.3, then RFC 3986 §6.2.2 and §6.2.3."""
    scheme = parts["scheme"].lower()
    default_port = {"http": "80", "https": "443"}.get(scheme)
    return {
        "scheme": scheme,
        "host": _percent_normalize(parts["host"]).lower(),
        "port": "" if parts["port"] == default_port else parts["port"],
        "path": _remove_dot_segments(_percent_normalize(parts["path"])) or "/",
        "query": None if parts["query"] is None else _percent_normalize(parts["query"]),
    }


def components(parts):
    """The values catu's component labels refer to."""
    path = parts["path"]
    slash = path.rfind("/")
    filename = path[slash + 1 :]
    dot = filename.rfind(".")
    return {
        0: parts["scheme"],
        1: parts["host"],
        2: parts["port"],
        3: path,
        4: parts["query"] or "",
        5: path[: max(slash, 0)],
        6: filename,
        7: filename if dot == -1 else filename[:dot],
        8: "" if dot == -1 else filename[dot:],
    }


def origin(url):
    n = normalize(split(url))
    return f"{n['scheme']}://{n['host']}{':' + n['port'] if n['port'] else ''}"


def _percent_normalize(s):
    """Uppercase percent-escapes and decode the ones that stand for unreserved characters."""

    def fix(m):
        char = chr(int(m.group(1), 16))
        return char if re.fullmatch(r"[A-Za-z0-9\-._~]", char) else m.group(0).upper()

    return re.sub(r"%([0-9a-fA-F]{2})", fix, s)


def _remove_dot_segments(path):
    """RFC 3986 §5.2.4."""
    out = []
    while path:
        if path.startswith("../"):
            path = path[3:]
        elif path.startswith("./") or path.startswith("/./"):
            path = path[2:]
        elif path == "/.":
            path = "/"
        elif path.startswith("/../"):
            path = path[3:]
            out and out.pop()
        elif path == "/..":
            path = "/"
            out and out.pop()
        elif path in (".", ".."):
            path = ""
        else:
            end = path.find("/", 1)
            end = len(path) if end == -1 else end
            out.append(path[:end])
            path = path[end:]
    return "".join(out)
