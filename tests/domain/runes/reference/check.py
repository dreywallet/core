"""Re-evaluate the committed raw-script corpus with the independently built ord binary."""
import json
import pathlib
import subprocess
import sys

corpus_path = pathlib.Path(__file__).resolve().parent.parent / "ord-0.27.1-vectors.json"
corpus = json.loads(corpus_path.read_text())
if corpus["reference"] != "ordinals/ord@1ad3f64dbc05b75e98665f411dbaa415f586e1c0 (0.27.1)":
    raise SystemExit("Unexpected protocol reference; review a reference change explicitly")
if len(sys.argv) != 2:
    raise SystemExit("Usage: python3 check.py /absolute/path/to/drey-rune-differential")
payload = "".join(json.dumps(case["scripts"]) + "\n" for case in corpus["cases"])
result = subprocess.run([sys.argv[1]], input=payload, text=True, capture_output=True,
                        check=True, timeout=30)
actual = [json.loads(line) for line in result.stdout.splitlines()]
if not actual or len(actual) != len(corpus["cases"]):
    raise SystemExit("Reference output coverage mismatch")
for index, (output, case) in enumerate(zip(actual, corpus["cases"])):
    if output != case["expected"]:
        raise SystemExit(f"Reference mismatch at vector {index}: {output!r} != {case['expected']!r}")
if not any(case["expected"]["kind"] == "cenotaph" for case in corpus["cases"]):
    raise SystemExit("Negative control coverage missing")
print(f"Verified {len(actual)} vectors against the independent pinned ord reference")
