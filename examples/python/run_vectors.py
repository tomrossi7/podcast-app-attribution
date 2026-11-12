# /// script
# requires-python = ">=3.10"
# dependencies = ["cbor2>=5.6", "cryptography>=42"]
# ///
"""Runs the verifier against every test vector.

    uv run examples/python/run_vectors.py

or, with cbor2 and cryptography installed, `python examples/python/run_vectors.py`.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from attribution import attach, mint, verify

vectors_dir = Path(__file__).parents[2] / "test-vectors"
suite = json.loads((vectors_dir / "vectors.json").read_text())
keys = json.loads((vectors_dir / suite["keys"]).read_text())
keys_for = lambda iss: keys if iss == suite["issuer"] else None

failures = 0
for v in suite["vectors"]:
    actual = verify(
        v["url"],
        keys_for,
        method=v["method"],
        now=v["now"],
        audiences_for=lambda iss: v.get("accepted_audiences", []),
    )
    ok = actual == v["expected"]
    failures += not ok
    print(f"{'ok  ' if ok else 'FAIL'} {v['name']}")
    if not ok:
        print(f"     expected {json.dumps(v['expected'])}\n     actual   {json.dumps(actual)}")

# A token minted here must verify here too.
private = next(k for k in json.loads((vectors_dir / "private-keys.json").read_text())["keys"] if k["kty"] == "EC")
url = "https://host.example/show/episode.mp3?id=42"
minted = verify(attach(url, mint(private, private["kid"], suite["issuer"], url=url)), keys_for)
ok = minted["verified"] and minted["catu"] and minted["catm"]
failures += not ok
print(f"{'ok  ' if ok else 'FAIL'} (minted here) {'' if ok else json.dumps(minted)}")

total = len(suite["vectors"]) + 1
print(f"\n{total - failures} of {total} passed")
sys.exit(1 if failures else 0)
