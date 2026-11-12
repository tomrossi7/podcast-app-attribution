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
  [v["name"], actual == v["expected"], "expected #{v["expected"].to_json}\n     actual   #{actual.to_json}"]
end

# A token minted here must verify here too, with either kind of key.
url = "https://host.example/show/episode.mp3?id=42"
JSON.parse(File.read(File.join(vectors_dir, "private-keys.json")))["keys"].each do |private_jwk|
  token = Attribution.mint(private_jwk, kid: private_jwk["kid"], iss: suite["issuer"], url: url)
  minted = Attribution.verify(Attribution.attach(url, token), keys_for: keys_for)
  results << ["(minted here, #{private_jwk["kty"]})", minted["verified"] && minted["catu"] && minted["catm"], minted.to_json]
end

results.each do |name, ok, detail|
  puts "#{ok ? "ok  " : "FAIL"} #{name}"
  puts "     #{detail}" unless ok
end
passed = results.count { |_, ok, _| ok }
puts "\n#{passed} of #{results.size} passed"
exit(passed == results.size)
