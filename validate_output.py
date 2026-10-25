
import csv
import json
from pathlib import Path

# Absolute project root path
ROOT = Path(
    r"D:\PradeepKumar B C\HackerRank Orchestrate"
    r"\hackerrank-orchestrate-october26"
)

output_file = ROOT / "output.csv"
sample_file = ROOT / "dataset" / "sample_output.csv"

required = ["case_id", "deletion_status", "steps_json"]

def load_csv(path):
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != required:
            raise ValueError(
                f"Unexpected columns in {path}: {reader.fieldnames}"
            )
        return list(reader)

output = load_csv(output_file)
samples = load_csv(sample_file)

ids = [r["case_id"] for r in output]
numbers = [int(x.split("_")[-1]) for x in ids]
by_id = {r["case_id"]: r for r in output}

print("Project root:", ROOT)
print("Output rows:", len(output))
print("Expected rows: 518")
print("Unique case IDs:", len(set(ids)))
print("Numerically sorted:", numbers == sorted(numbers))
print("Valid statuses:", all(
    r["deletion_status"] in {
        "COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"
    }
    for r in output
))

status_matches = 0
step_matches = 0
missing = []

for expected in samples:
    actual = by_id.get(expected["case_id"])

    if actual is None:
        missing.append(expected["case_id"])
        continue

    if actual["deletion_status"] == expected["deletion_status"]:
        status_matches += 1

    try:
        if json.loads(actual["steps_json"]) == json.loads(
            expected["steps_json"]
        ):
            step_matches += 1
    except (ValueError, TypeError):
        pass

print(f"\nPublic samples: {len(samples)}")
print(f"Status matches: {status_matches}/{len(samples)}")
print(f"Exact steps_json matches: {step_matches}/{len(samples)}")
print("Missing sample cases:", missing or "None")
