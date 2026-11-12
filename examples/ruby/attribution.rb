# Minting and verifying Verified App Attribution tokens. Standard library only (Ruby 3.1 or
# later, built against OpenSSL 3).
#
#   token = Attribution.mint(private_jwk, kid: "2026-11", iss: "https://exampleplayer.com", url: url)
#   Net::HTTP.get(URI(Attribution.attach(url, token)))
#
#   result = Attribution.verify(url, keys_for: ->(iss) { cached_key_set(iss) })
#   # {"verified" => true, "iss" => ..., "kid" => ..., "exp" => ..., "catu" => ..., "catm" => ..., "aud" => ...}
#   # or {"verified" => false, "reason" => ...}
#
# `keys_for` returns the cached JWK Set for an issuer, or nil when none is cached. It must not
# fetch: keys are refreshed in the background, never while a request waits.

require "openssl"
require "securerandom"
require "stringio"
require_relative "cbor"

module Attribution
  # CWT and CAT claim labels (IANA CWT Claims registry).
  ISS, AUD, EXP, NBF, IAT, CTI, CATV, CATU, CATM = 1, 3, 4, 5, 6, 7, 310, 312, 313
  # COSE header labels and algorithm values.
  ALG, CRIT, KID, ES256, EDDSA = 1, 2, 4, -7, -8

  MAX_LIFETIME = 86_400
  ISSUER = /\Ahttps:\/\/[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]{1,5})?\z/

  Unverified = Class.new(StandardError)

  module_function

  # --- minting ----------------------------------------------------------------------------------

  # A per-request token when `url` is given, otherwise a session token.
  def mint(private_jwk, kid:, iss:, url: nil, methods: %w[GET HEAD], aud: nil, lifetime: 300, now: Time.now.to_i)
    claims = { ISS => iss, EXP => now + lifetime, IAT => now, CTI => SecureRandom.bytes(16), CATV => 1 }
    claims[AUD] = aud if aud
    if url
      claims[CATU] = exact_url(url)
      claims[CATM] = methods
    end
    protected_header = { ALG => algorithm_for(private_jwk), KID => kid.b }
    cose = sign_cose(protected_header: protected_header, payload: CBOR.encode(claims), private_jwk: private_jwk)
    base64url(CBOR.encode(CBOR::Tagged.new(18, cose)))
  end

  # A catu that matches exactly this URL: scheme, host, path and query, after removing any CAT
  # parameter and normalizing. Port is left out, so any port matches.
  def exact_url(url)
    parts = split(url)
    n = normalize(parts.merge(query: extract_tokens(parts[:query]).last))
    { 0 => { 0 => n[:scheme] }, 1 => { 0 => n[:host] }, 3 => { 0 => n[:path] }, 4 => { 0 => n[:query] || "" } }
  end

  # Appends the token, leaving the URL alone if it already carries one.
  def attach(url, token)
    query = split(url)[:query]
    return url if extract_tokens(query).first.any?

    "#{url}#{query ? "&" : "?"}CAT=#{token}"
  end

  # COSE_Sign1 (RFC 9052 §4.2): [protected header as bytes, unprotected header, payload, signature].
  def sign_cose(protected_header:, payload:, private_jwk:, unprotected_header: {})
    protected_bytes = CBOR.encode(protected_header)
    data = to_be_signed(protected_bytes, payload)
    signature =
      if algorithm_for(private_jwk) == ES256
        der = ec_private_key(private_jwk).sign("SHA256", data)
        # DER → the 64-byte r ‖ s form COSE uses.
        OpenSSL::ASN1.decode(der).value.map { |int| int.value.to_s(2).rjust(32, "\0".b) }.join
      else
        OpenSSL::PKey.new_raw_private_key("ED25519", unbase64url(private_jwk["d"])).sign(nil, data)
      end
    [protected_bytes, unprotected_header, payload, signature]
  end

  # --- verifying --------------------------------------------------------------------------------

  def verify(url, keys_for:, method: "GET", audiences_for: ->(_iss) { [] }, now: Time.now.to_i)
    check(url, keys_for, method, audiences_for, now)
  rescue Unverified => e
    { "verified" => false, "reason" => e.message }
  end

  def check(url, keys_for, method, audiences_for, now)
    received = split(url)
    tokens, query = extract_tokens(received[:query])
    fail!("malformed") unless tokens.size == 1
    without_token = received.merge(query: query)

    # 1. Decode.
    protected_bytes, protected_header, unprotected_header, payload, signature = decode_token(tokens.first)
    alg = protected_header[ALG]
    fail!("malformed") unless [ES256, EDDSA].include?(alg)
    fail!("malformed") if protected_header.key?(CRIT) # no extensions are understood
    fail!("malformed") if (protected_header.keys & unprotected_header.keys).any?
    kid = protected_header[KID] || unprotected_header[KID]
    fail!("malformed") unless bytes?(kid)
    kid = kid.dup.force_encoding(Encoding::UTF_8)
    fail!("malformed") unless kid.valid_encoding?
    claims = decode_map(payload)

    # 2. Claims.
    iss, exp, iat, cti = claims.values_at(ISS, EXP, IAT, CTI)
    nbf, aud, catu, catm = claims.values_at(NBF, AUD, CATU, CATM)
    well_formed =
      text?(iss) && ISSUER.match?(iss) && !iss.end_with?(":443") &&
      exp.is_a?(Integer) && iat.is_a?(Integer) &&
      bytes?(cti) && cti.bytesize >= 8 &&
      claims[CATV] == 1 &&
      (nbf.nil? || nbf.is_a?(Integer)) &&
      (aud.nil? || text?(aud)) &&
      (catu.nil? || url_restriction?(catu)) &&
      (catm.nil? || (catm.is_a?(Array) && catm.any? && catm.all? { |m| text?(m) })) &&
      iat < exp && exp <= iat + MAX_LIFETIME
    fail!("malformed") unless well_formed

    # 3. Time, with no leeway.
    fail!("expired") unless now < exp
    fail!("not_yet_valid") unless nbf.nil? || nbf <= now

    # 4. The key, looked up only under the token's own issuer.
    key_set = keys_for.call(iss) || { "keys" => [] }
    jwk = key_set["keys"].find { |k| k["kid"] == kid && usable?(k, alg) }
    fail!("key_unavailable") unless jwk

    # 5. Signature.
    fail!("bad_signature") unless signature_valid?(alg, jwk, to_be_signed(protected_bytes, payload), signature)

    # 6. Restrictions, against the request as received.
    if catu
      # Normalized first; then with the path and query exactly as received, for issuers that
      # bind them verbatim. Scheme, host and port are always compared normalized.
      normalized = normalize(without_token)
      verbatim = normalized.merge(path: without_token[:path], query: without_token[:query])
      fail!("url_mismatch") unless [normalized, verbatim].any? { |parts| url_matches?(catu, components(parts)) }
    end
    fail!("method_mismatch") unless catm.nil? || catm.include?(method)
    fail!("audience_mismatch") unless aud.nil? || aud == origin(url) || audiences_for.call(iss).include?(aud)

    {
      "verified" => true,
      "iss" => iss,
      "kid" => kid,
      "exp" => exp,
      "catu" => catu ? true : nil,
      "catm" => catm ? true : nil,
      "aud" => aud ? true : nil
    }
  end

  def fail!(reason)
    raise Unverified, reason
  end

  # base64url (padding optional) → CBOR → COSE_Sign1, untagged, tagged 18, or tagged 61 around 18.
  def decode_token(value)
    encoded = decode_once(value).sub(/=+\z/, "")
    fail!("malformed") unless encoded.match?(/\A[A-Za-z0-9_-]+\z/) && encoded.size % 4 != 1

    item = decode_cbor(unbase64url(encoded))
    item = item.value if item.is_a?(CBOR::Tagged) && item.tag == 61
    item = item.value if item.is_a?(CBOR::Tagged) && item.tag == 18

    fail!("malformed") unless item.is_a?(Array) && item.size == 4
    protected_bytes, unprotected_header, payload, signature = item
    fail!("malformed") unless bytes?(protected_bytes) && unprotected_header.is_a?(Hash) && bytes?(payload) && bytes?(signature)

    [protected_bytes, decode_map(protected_bytes), unprotected_header, payload, signature]
  end

  def decode_cbor(bytes)
    CBOR.decode(bytes)
  rescue CBOR::Error
    fail!("malformed")
  end

  def decode_map(bytes)
    map = decode_cbor(bytes)
    fail!("malformed") unless map.is_a?(Hash)
    map
  end

  def bytes?(value)
    value.is_a?(String) && value.encoding == Encoding::BINARY
  end

  def text?(value)
    value.is_a?(String) && value.encoding != Encoding::BINARY
  end

  # Sig_structure (RFC 9052 §4.4) with empty external data.
  def to_be_signed(protected_bytes, payload)
    CBOR.encode(["Signature1", protected_bytes, "".b, payload])
  end

  # A published key that does not fit the token's algorithm is treated as absent.
  def usable?(jwk, alg)
    kty, crv, name = alg == ES256 ? %w[EC P-256 ES256] : %w[OKP Ed25519 EdDSA]
    jwk["kty"] == kty && jwk["crv"] == crv && jwk["use"] == "sig" &&
      jwk.fetch("alg", name) == name && jwk.fetch("key_ops", ["verify"]).include?("verify")
  end

  def signature_valid?(alg, jwk, data, signature)
    if alg == ES256
      return false unless signature.bytesize == 64

      # r ‖ s → DER, which is what OpenSSL verifies.
      der = OpenSSL::ASN1::Sequence([signature[0, 32], signature[32, 32]].map { |n| OpenSSL::ASN1::Integer(OpenSSL::BN.new(n, 2)) }).to_der
      ec_public_key(jwk).verify("SHA256", der, data)
    else
      OpenSSL::PKey.new_raw_public_key("ED25519", unbase64url(jwk["x"])).verify(nil, signature, data)
    end
  rescue OpenSSL::OpenSSLError, ArgumentError
    false
  end

  def algorithm_for(jwk)
    return ES256 if jwk["kty"] == "EC" && jwk["crv"] == "P-256"
    return EDDSA if jwk["kty"] == "OKP" && jwk["crv"] == "Ed25519"

    raise ArgumentError, "unsupported key type"
  end

  # OpenSSL reads keys from DER, so wrap the JWK's raw numbers in the standard structures:
  # SubjectPublicKeyInfo for a public key, ECPrivateKey (RFC 5915) for a private one.
  def ec_public_key(jwk)
    algorithm = OpenSSL::ASN1::Sequence([OpenSSL::ASN1::ObjectId("id-ecPublicKey"), OpenSSL::ASN1::ObjectId("prime256v1")])
    OpenSSL::PKey.read(OpenSSL::ASN1::Sequence([algorithm, OpenSSL::ASN1::BitString(ec_point(jwk))]).to_der)
  end

  def ec_private_key(jwk)
    explicit = ->(value, tag) { OpenSSL::ASN1::ASN1Data.new([value], tag, :CONTEXT_SPECIFIC) }
    OpenSSL::PKey.read(OpenSSL::ASN1::Sequence([
      OpenSSL::ASN1::Integer(1),
      OpenSSL::ASN1::OctetString(unbase64url(jwk["d"])),
      explicit.(OpenSSL::ASN1::ObjectId("prime256v1"), 0),
      explicit.(OpenSSL::ASN1::BitString(ec_point(jwk)), 1)
    ]).to_der)
  end

  # The uncompressed point: 0x04, then x and y as 32 bytes each.
  def ec_point(jwk)
    x, y = unbase64url(jwk["x"]), unbase64url(jwk["y"])
    raise ArgumentError, "coordinates must be 32 bytes" unless x.bytesize == 32 && y.bytesize == 32

    "\x04".b + x + y
  end

  def base64url(bytes)
    [bytes].pack("m0").tr("+/", "-_").delete("=")
  end

  def unbase64url(text)
    text.tr("-_", "+/").unpack1("m").b
  end

  # catu: a map from component label to a map of match type → expected value.
  def url_restriction?(catu)
    catu.is_a?(Hash) && catu.all? { |part, match| part.is_a?(Integer) && match.is_a?(Hash) }
  end

  def url_matches?(catu, parts)
    catu.all? do |part, match|
      parts.key?(part) && match.all? { |type, expected| component_matches?(type, expected, parts[part]) }
    end
  end

  # Exact, prefix, suffix, contains and SHA-256. A match type this verifier does not support
  # (regular expression, SHA-512/256) fails the match, as CTA-5007-B requires.
  def component_matches?(type, expected, actual)
    return bytes?(expected) && OpenSSL::Digest::SHA256.digest(actual) == expected if type == -1
    return false unless text?(expected)

    case type
    when 0 then actual == expected
    when 1 then actual.start_with?(expected)
    when 2 then actual.end_with?(expected)
    when 3 then actual.include?(expected)
    else false
    end
  end

  # --- URLs -------------------------------------------------------------------------------------
  # Handled as strings on purpose: a general-purpose URL class rewrites what it parses, and "the
  # URL as received" matters here.

  # RFC 3986 Appendix B, plus the authority split into host and port.
  def split(url)
    m = url.match(/\A(?:([^:\/?#]+):)?(?:\/\/([^\/?#]*))?([^?#]*)(?:\?([^#]*))?/)
    host, port = m[2].to_s.sub(/\A.*@/, "").match(/\A(\[[^\]]*\]|[^:]*)(?::(.*))?\z/).captures
    { scheme: m[1].to_s, host: host, port: port.to_s, path: m[3], query: m[4] }
  end

  # The values of the CAT parameters in a query, and the query without them. The query is split
  # on "&"; a name is everything before the first "=", percent-decoded once.
  def extract_tokens(query)
    return [[], nil] if query.nil?

    tokens, rest = query.split("&", -1).partition { |field| decode_once(field.split("=", 2).first.to_s) == "CAT" }
    [tokens.map { |field| field.split("=", 2)[1].to_s }, rest.empty? ? nil : rest.join("&")]
  end

  # RFC 9110 §4.2.3, then RFC 3986 §6.2.2 and §6.2.3.
  def normalize(parts)
    scheme = parts[:scheme].downcase
    path = remove_dot_segments(percent_normalize(parts[:path]))
    {
      scheme: scheme,
      host: percent_normalize(parts[:host]).downcase,
      port: parts[:port] == { "http" => "80", "https" => "443" }[scheme] ? "" : parts[:port],
      path: path.empty? ? "/" : path,
      query: parts[:query] && percent_normalize(parts[:query])
    }
  end

  # The values catu's component labels refer to.
  def components(parts)
    path = parts[:path]
    slash = path.rindex("/")
    filename = slash ? path[(slash + 1)..] : path
    dot = filename.rindex(".")
    {
      0 => parts[:scheme],
      1 => parts[:host],
      2 => parts[:port],
      3 => path,
      4 => parts[:query] || "",
      5 => path[0, slash || 0],
      6 => filename,
      7 => dot ? filename[0, dot] : filename,
      8 => dot ? filename[dot..] : ""
    }
  end

  # scheme://host[:port], with the port only when it is not the scheme's default.
  def origin(url)
    n = normalize(split(url))
    "#{n[:scheme]}://#{n[:host]}#{":#{n[:port]}" unless n[:port].empty?}"
  end

  def decode_once(text)
    text.gsub(/%([0-9a-fA-F]{2})/) { $1.hex.chr }
  end

  # Uppercase the hex digits of percent-escapes and decode the ones that stand for unreserved
  # characters (letters, digits, "-", ".", "_", "~").
  def percent_normalize(text)
    text.gsub(/%([0-9a-fA-F]{2})/) do |escape|
      char = $1.hex.chr
      char.match?(/[A-Za-z0-9\-._~]/) ? char : escape.upcase
    end
  end

  # RFC 3986 §5.2.4.
  def remove_dot_segments(path)
    input = path.dup
    out = []
    until input.empty?
      if input.start_with?("../") then input = input[3..]
      elsif input.start_with?("./", "/./") then input = input[2..]
      elsif input == "/." then input = "/"
      elsif input.start_with?("/../")
        input = input[3..]
        out.pop
      elsif input == "/.."
        input = "/"
        out.pop
      elsif %w[. ..].include?(input) then input = ""
      else
        segment_end = input.index("/", 1) || input.size
        out << input[0, segment_end]
        input = input[segment_end..]
      end
    end
    out.join
  end
end
