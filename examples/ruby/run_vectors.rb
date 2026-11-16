# Runs the verifier against every test vector.
#
#   ruby examples/ruby/run_vectors.rb

require "json"
require_relative "attribution"

vectors_dir = File.expand_path("../../test-vectors", __dir__)
suite = JSON.parse(File.read(File.join(vectors_dir, "vectors.json")))
keys = JSON.parse(File.read(File.join(vectors_dir, suite["keys"])))
keys_for = ->(iss) { keys if iss == suite["issuer"] }

results = suite["vectors"].map do |v|
  actual = Attribution.verify(
    v["url"],
    keys_for: keys_for,
    method: v["method"],
    now: v["now"],
    audiences_for: ->(_iss) { v.fetch("accepted_audiences", []) }
  )
  # Whether the request is verified, and as whom, is what has to match. The reason is diagnostic.
  ok = actual.values_at("verified", "iss") == v["expected"].values_at("verified", "iss")
  [v["name"], ok, "expected #{v["expected"].to_json}\n     actual   #{actual.to_json}"]
end

# A token minted here must verify here too.
url = "https://host.example/show/episode.mp3?id=42"
private_jwk = JSON.parse(File.read(File.join(vectors_dir, "private-keys.json")))["keys"].find { |k| k["use"] == "sig" }
token = Attribution.mint(private_jwk, kid: private_jwk["kid"], iss: suite["issuer"], url: url)
minted = Attribution.verify(Attribution.attach(url, token), keys_for: keys_for)
results << ["(minted here)", minted == { "verified" => true, "iss" => suite["issuer"] }, minted.to_json]

results.each do |name, ok, detail|
  puts "#{ok ? "ok  " : "FAIL"} #{name}"
  puts "     #{detail}" unless ok
end
passed = results.count { |_, ok, _| ok }
puts "\n#{passed} of #{results.size} passed"
exit(passed == results.size)
