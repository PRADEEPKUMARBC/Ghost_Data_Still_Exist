import argparse
import csv
import json
import re
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[1]
ROOT = CODE_DIR.parent
sys.path.insert(0, str(CODE_DIR))

import main as generator

OUTPUT = ROOT / "output.csv"
REQUESTS = ROOT / "dataset" / "deletion_requests.csv"
SAMPLE_REQUESTS = ROOT / "dataset" / "sample_deletion_requests.csv"
SAMPLE_OUTPUT = ROOT / "dataset" / "sample_output.csv"
EVALUATION_DIR = CODE_DIR / "evaluation"
EVALUATION_REPORT = EVALUATION_DIR / "evaluation_report.md"
USAGE_REPORT = EVALUATION_DIR / "usage_report.md"
OUTPUT_HEADER = ["case_id", "deletion_status", "steps_json"]
STEP_FIELDS = generator.STEP_FIELDS
CORE_FIELDS = ("phase", "system_id", "resource_id", "operation", "state")


def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        return list(reader), reader.fieldnames


def step_core(step):
    return tuple(step.get(field) for field in CORE_FIELDS)


def step_signature(step, include_number=False):
    fields = ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]
    if include_number:
        fields.append("step_no")
    return tuple(step.get(field) for field in fields)


def validate_output(output_path=OUTPUT, request_path=REQUESTS):
    requests, _ = read_csv(request_path)
    expected_ids = [row["case_id"] for row in requests]
    expected_id_set = set(expected_ids)
    manifest = generator.load_manifest()
    activity_ids = {row["activity_id"]: row for row in generator.read_csv(generator.ACTIVITY)}
    audit_ids = {row["audit_id"]: row for row in generator.read_csv(generator.AUDIT_LOG)}
    if not output_path.exists():
        return [f"Missing output file: {output_path}"], {"rows": 0, "header_ok": False}
    rows, header = read_csv(output_path)
    issues = []
    semantic_warnings = []
    if header != OUTPUT_HEADER:
        issues.append(f"Header mismatch: expected {OUTPUT_HEADER}, got {header}")
    output_ids = [row.get("case_id", "") for row in rows]
    if len(rows) != 518:
        issues.append(f"Expected 518 rows, found {len(rows)}")
    duplicate_ids = sorted(case_id for case_id, count in Counter(output_ids).items() if count > 1)
    if duplicate_ids:
        issues.append(f"Duplicate case IDs: {duplicate_ids}")
    missing_ids = sorted(expected_id_set - set(output_ids), key=generator.case_sort_key)
    extra_ids = sorted(set(output_ids) - expected_id_set, key=generator.case_sort_key)
    if missing_ids:
        issues.append(f"Missing case IDs: {missing_ids}")
    if extra_ids:
        issues.append(f"Unexpected case IDs: {extra_ids}")
    if output_ids != sorted(output_ids, key=generator.case_sort_key):
        issues.append("Rows are not sorted by numeric case ID")
    requests_by_id = {row["case_id"]: row for row in requests}
    allowed_statuses = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
    for row_index, row in enumerate(rows, start=2):
        case_id = row.get("case_id", "")
        status = row.get("deletion_status", "")
        if status not in allowed_statuses:
            issues.append(f"Row {row_index} ({case_id}): invalid status {status!r}")
        try:
            steps = json.loads(row.get("steps_json", ""))
        except (json.JSONDecodeError, TypeError) as error:
            issues.append(f"Row {row_index} ({case_id}): invalid steps_json: {error}")
            continue
        if not isinstance(steps, list):
            issues.append(f"Row {row_index} ({case_id}): steps_json is not an array")
            continue
        expected_request = requests_by_id.get(case_id)
        audit_at = generator.parse_iso(expected_request.get("audit_at")) if expected_request else None
        if expected_request and not generator.authorizes_deletion(expected_request.get("request_text", "")):
            if status != "NOT_APPLICABLE" or steps:
                issues.append(
                    f"Row {row_index} ({case_id}): non-deletion request must be NOT_APPLICABLE with []"
                )
        elif expected_request and status == "NOT_APPLICABLE":
            issues.append(
                f"Row {row_index} ({case_id}): deletion-authorizing request cannot be NOT_APPLICABLE"
            )
        previous_sort_key = None
        steps_by_resource = {}
        operations_by_resource = {}
        for index, step in enumerate(steps, start=1):
            if not isinstance(step, dict):
                issues.append(f"Row {row_index} ({case_id}): step {index} is not an object")
                continue
            if set(step) != STEP_FIELDS:
                issues.append(
                    f"Row {row_index} ({case_id}): step {index} fields differ "
                    f"(missing={sorted(STEP_FIELDS - set(step))}, extra={sorted(set(step) - STEP_FIELDS)})"
                )
            if step.get("step_no") != index:
                issues.append(f"Row {row_index} ({case_id}): step numbers are not consecutive")
            operation = step.get("operation")
            expected_phase_state = generator.OPERATION_STATES.get(operation)
            if step.get("phase") not in generator.ALLOWED_PHASES:
                issues.append(f"Row {row_index} ({case_id}): invalid phase at step {index}")
            if expected_phase_state is None:
                issues.append(f"Row {row_index} ({case_id}): invalid operation at step {index}")
            elif (step.get("phase"), step.get("state")) != expected_phase_state:
                issues.append(f"Row {row_index} ({case_id}): phase/state mismatch at step {index}")
            if expected_phase_state is not None and step.get("phase") in generator.ALLOWED_PHASES:
                sort_key = generator.normalized_step_sort(step)
                if previous_sort_key is not None and sort_key < previous_sort_key:
                    issues.append(f"Row {row_index} ({case_id}): steps are out of required order")
                previous_sort_key = sort_key
            evidence_id = step.get("evidence_id", "")
            if step.get("phase") == "FINDING" or (status == "COMPLETE" and step.get("phase") == "VERIFICATION"):
                if not evidence_id:
                    issues.append(f"Row {row_index} ({case_id}): required evidence missing at step {index}")
            if step.get("phase") == "REMEDIATION" or (
                status == "INCOMPLETE" and step.get("phase") == "VERIFICATION"
            ):
                if evidence_id != "":
                    issues.append(f"Row {row_index} ({case_id}): future step cites evidence at step {index}")
            if evidence_id:
                if evidence_id in manifest:
                    cited_at = generator.parse_iso(manifest[evidence_id].get("captured_at"))
                elif evidence_id in activity_ids:
                    cited_at = generator.parse_iso(activity_ids[evidence_id].get("event_time"))
                elif evidence_id in audit_ids:
                    cited_at = generator.parse_iso(audit_ids[evidence_id].get("event_time"))
                else:
                    cited_at = None
                    issues.append(f"Row {row_index} ({case_id}): invalid evidence ID {evidence_id!r}")
                if cited_at and audit_at and cited_at > audit_at:
                    issues.append(f"Row {row_index} ({case_id}): evidence {evidence_id} is after audit_at")
            if operation in {"DELETE_RECORD", "REDACT_RECORD", "ANONYMIZE_RECORD", "DISABLE_DATA_FLOW", "BLOCK_RESTORE"}:
                steps_by_resource.setdefault(step.get("resource_id"), set()).add(operation)
            if step.get("resource_id"):
                operations_by_resource.setdefault(step.get("resource_id"), set()).add(operation)
        if status == "NOT_APPLICABLE" and steps:
            issues.append(f"Row {row_index} ({case_id}): NOT_APPLICABLE must have []")
        if status == "COMPLETE":
            if any(step.get("phase") != "VERIFICATION" for step in steps):
                issues.append(f"Row {row_index} ({case_id}): COMPLETE contains non-verification steps")
            if not steps:
                issues.append(f"Row {row_index} ({case_id}): COMPLETE has no evidence-backed checks")
        if status == "INCOMPLETE":
            if not any(step.get("phase") == "FINDING" for step in steps):
                semantic_warnings.append(
                    f"Row {row_index} ({case_id}): INCOMPLETE has no evidence-backed finding; "
                    "no resource or proof was fabricated."
                )
            for resource_id, operations in operations_by_resource.items():
                finding_ops = {
                    operation
                    for operation in operations
                    if generator.OPERATION_STATES.get(operation, (None,))[0] == "FINDING"
                }
                if finding_ops and not operations & {
                    "DELETE_RECORD",
                    "REDACT_RECORD",
                    "ANONYMIZE_RECORD",
                    "DISABLE_DATA_FLOW",
                    "BLOCK_RESTORE",
                }:
                    issues.append(
                        f"Row {row_index} ({case_id}): finding for {resource_id} has no remediation"
                    )
                if finding_ops and not any(
                    operation.startswith("VERIFY_") for operation in operations
                ):
                    issues.append(
                        f"Row {row_index} ({case_id}): finding for {resource_id} has no future verification"
                    )
            for resource_id, operations in steps_by_resource.items():
                if not any(
                    step.get("phase") == "VERIFICATION" and step.get("resource_id") == resource_id
                    for step in steps
                ):
                    issues.append(f"Row {row_index} ({case_id}): no future verification for {resource_id}")
                if not operations:
                    issues.append(f"Row {row_index} ({case_id}): missing remediation for {resource_id}")
    return issues, {
        "rows": len(rows),
        "header_ok": header == OUTPUT_HEADER,
        "semantic_warnings": semantic_warnings,
    }


def predict_public_samples():
    requests, _ = read_csv(SAMPLE_REQUESTS)
    expected_rows, _ = read_csv(SAMPLE_OUTPUT)
    expected = {row["case_id"]: row for row in expected_rows}
    manifest = generator.load_manifest()
    evidence_catalog, _ = generator.build_evidence_catalog(manifest)
    email_to_users, identifiers_by_user, current_rows, audit_rows = generator.load_identity_data()
    rules = generator.load_rules()
    actual = {}
    for row in requests:
        status, steps = generator.build_result(
            row,
            email_to_users,
            identifiers_by_user,
            current_rows,
            audit_rows,
            evidence_catalog,
            rules,
        )
        actual[row["case_id"]] = {
            "deletion_status": status,
            "steps": steps,
        }
    return requests, expected, actual, manifest


def score_public_samples(requests, expected, actual):
    status_correct = 0
    exact_correct = 0
    sequence_correct = 0
    expected_signatures = Counter()
    actual_signatures = Counter()
    aligned_field_matches = 0
    aligned_field_slots = 0
    evidence_mismatches = 0
    missing_steps = 0
    extra_steps = 0
    out_of_order_cases = 0
    per_case = []
    for request in requests:
        case_id = request["case_id"]
        want = json.loads(expected[case_id]["steps_json"])
        got = actual[case_id]["steps"]
        expected_status = expected[case_id]["deletion_status"]
        actual_status = actual[case_id]["deletion_status"]
        status_correct += expected_status == actual_status
        exact_correct += expected_status == actual_status and want == got
        want_ordered = [step_signature(step, include_number=True) for step in want]
        got_ordered = [step_signature(step, include_number=True) for step in got]
        sequence_correct += want_ordered == got_ordered
        expected_signatures.update(step_signature(step) for step in want)
        actual_signatures.update(step_signature(step) for step in got)
        max_steps = max(len(want), len(got))
        for index in range(max_steps):
            expected_step = want[index] if index < len(want) else {}
            actual_step = got[index] if index < len(got) else {}
            for field in STEP_FIELDS:
                aligned_field_slots += 1
                aligned_field_matches += (
                    index < len(want)
                    and index < len(got)
                    and expected_step.get(field) == actual_step.get(field)
                )
        expected_core = Counter(step_core(step) for step in want)
        actual_core = Counter(step_core(step) for step in got)
        missing_steps += sum((expected_core - actual_core).values())
        extra_steps += sum((actual_core - expected_core).values())
        if expected_core == actual_core and want_ordered != got_ordered:
            out_of_order_cases += 1
        actual_by_core = {}
        for step in got:
            actual_by_core.setdefault(step_core(step), []).append(step)
        for step in want:
            matches = actual_by_core.get(step_core(step), [])
            if matches:
                candidate = matches.pop(0)
                if step.get("evidence_id") != candidate.get("evidence_id"):
                    evidence_mismatches += 1
        per_case.append(
            {
                "case_id": case_id,
                "expected_status": expected_status,
                "actual_status": actual_status,
                "expected": want,
                "actual": got,
                "missing": expected_core - actual_core,
                "extra": actual_core - expected_core,
                "out_of_order": expected_core == actual_core and want_ordered != got_ordered,
            }
        )
    true_positive = sum((expected_signatures & actual_signatures).values())
    precision = true_positive / sum(actual_signatures.values()) if actual_signatures else 0.0
    recall = true_positive / sum(expected_signatures.values()) if expected_signatures else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "case_count": len(requests),
        "status_correct": status_correct,
        "status_accuracy": status_correct / len(requests) if requests else 0.0,
        "exact_correct": exact_correct,
        "exact_accuracy": exact_correct / len(requests) if requests else 0.0,
        "sequence_correct": sequence_correct,
        "sequence_accuracy": sequence_correct / len(requests) if requests else 0.0,
        "step_precision": precision,
        "step_recall": recall,
        "step_f1": f1,
        "field_matches": aligned_field_matches,
        "field_slots": aligned_field_slots,
        "field_accuracy": aligned_field_matches / aligned_field_slots if aligned_field_slots else 0.0,
        "evidence_mismatches": evidence_mismatches,
        "missing_steps": missing_steps,
        "extra_steps": extra_steps,
        "out_of_order_cases": out_of_order_cases,
        "per_case": per_case,
    }


def fmt_steps(steps):
    if not steps:
        return "`[]`"
    return "`" + "; ".join(
        f"{step.get('phase')}:{step.get('operation')}:{step.get('system_id')}:"
        f"{step.get('resource_id')}:{step.get('state')}:{step.get('evidence_id')}"
        for step in steps
    ) + "`"


def mismatch_cause(case, request, manifest):
    expected = case["expected"]
    actual = case["actual"]
    missing_resources = {
        step.get("resource_id") for step in expected
    } - {step.get("resource_id") for step in actual}
    extra_resources = {
        step.get("resource_id") for step in actual
    } - {step.get("resource_id") for step in expected}
    if case["expected_status"] != case["actual_status"] and not expected and actual:
        return "Request-authorization classification differs; inspect the request-language rule."
    if missing_resources:
        expected_evidence = [
            step.get("evidence_id")
            for step in expected
            if step.get("resource_id") in missing_resources and step.get("evidence_id")
        ]
        file_types = {
            Path(manifest[evidence_id]["file_path"]).suffix.casefold()
            for evidence_id in expected_evidence
            if evidence_id in manifest
        }
        if ".png" in file_types:
            return "Expected resource is supported by screenshot evidence; image OCR is not implemented."
        if ".pdf" in file_types:
            return "Expected resource is in a PDF artifact; inspect document block segmentation and identity linkage."
        return (
            "Expected resource is not linked by a subject-scoped record at audit_at; "
            "absence/current-state mapping remains unresolved."
        )
    if extra_resources:
        return "Actual-only resource likely reflects an over-broad identity/correlation link; inspect the exact record fields."
    if case["missing"] or case["extra"]:
        return "Resource was found, but policy category or state classification differs."
    if any(
        step.get("evidence_id") != other.get("evidence_id")
        for step, other in zip(expected, actual)
    ):
        return "Step content matches but the supporting evidence selection differs."
    return "Step sequence or numbering differs."


def evidence_context(case, manifest, request):
    ids = sorted(
        {
            step.get("evidence_id")
            for step in case["expected"]
            if step.get("evidence_id")
        }
    )
    contexts = []
    audit_at = generator.parse_iso(request.get("audit_at"))
    for evidence_id in ids:
        item = manifest.get(evidence_id)
        if not item:
            continue
        captured_at = generator.parse_iso(item.get("captured_at"))
        relation = "before/equal cutoff" if captured_at and audit_at and captured_at <= audit_at else "after/missing cutoff"
        contexts.append(
            f"{evidence_id} `{item.get('file_path')}` captured `{item.get('captured_at')}` ({relation})"
        )
    return ", ".join(contexts) or "No file-backed expected evidence ID"


def build_evaluation_report(
    requests,
    expected,
    actual,
    manifest,
    metrics,
    validation_issues,
    validation_warnings,
    test_result,
):
    output_rows, _ = read_csv(OUTPUT)
    statuses = Counter(row["deletion_status"] for row in output_rows)
    mismatches = [
        case
        for case in metrics["per_case"]
        if case["expected_status"] != case["actual_status"]
        or case["expected"] != case["actual"]
    ]
    lines = [
        "# Evaluation Report",
        "",
        "## Public sample comparison",
        "",
        "The 32 public sample requests were evaluated in memory with the same deterministic "
        "predictor used by `code/main.py`; public labels were not injected into production output.",
        "",
        f"- Status accuracy: {metrics['status_correct']}/{metrics['case_count']} "
        f"({metrics['status_accuracy']:.1%}).",
        f"- Exact status + step-array accuracy: {metrics['exact_correct']}/{metrics['case_count']} "
        f"({metrics['exact_accuracy']:.1%}); JSON objects were compared independent of key order, "
        "while array order was preserved.",
        f"- Exact sequence accuracy: {metrics['sequence_correct']}/{metrics['case_count']} "
        f"({metrics['sequence_accuracy']:.1%}).",
        f"- Step precision / recall / F1 (multiset of full step fields except `step_no`): "
        f"{metrics['step_precision']:.1%} / {metrics['step_recall']:.1%} / {metrics['step_f1']:.1%}.",
        f"- Field accuracy (seven fields compared by array position, missing/extra steps count as wrong): "
        f"{metrics['field_matches']}/{metrics['field_slots']} ({metrics['field_accuracy']:.1%}).",
        f"- Evidence-reference mismatches on otherwise matching step identities: "
        f"{metrics['evidence_mismatches']}.",
        f"- Missing expected / extra actual core steps: {metrics['missing_steps']} / {metrics['extra_steps']}.",
        f"- Cases with the same step identities but incorrect sequence: {metrics['out_of_order_cases']}.",
        "",
        "## Mismatch-by-mismatch investigation",
        "",
        "Each row includes the exact expected and predicted status/step signatures, the expected "
        "evidence artifact and its capture-time relation to `audit_at`, and a cause category grounded "
        "in the observed missing/extra resources or fields. A cause category is not asserted as a "
        "confirmed defect when subject linkage is absent.",
        "",
        "| Case | Expected | Actual | Expected evidence and timing | Likely cause |",
        "|---|---|---|---|---|",
    ]
    request_map = {row["case_id"]: row for row in requests}
    for case in mismatches:
        request = request_map[case["case_id"]]
        expected_summary = f"{case['expected_status']} {fmt_steps(case['expected'])}"
        actual_summary = f"{case['actual_status']} {fmt_steps(case['actual'])}"
        cause = mismatch_cause(case, request, manifest)
        context = evidence_context(case, manifest, request)
        lines.append(
            f"| {case['case_id']} | {expected_summary} | {actual_summary} | "
            f"{context} | {cause} |"
        )
    lines.extend(
        [
            "",
            "## Root-output structural validation",
            "",
            f"- Generated output rows by status: `{dict(sorted(statuses.items()))}`.",
            f"- Structural/semantic validator: {'PASS' if not validation_issues else 'FAIL'} "
            f"({len(validation_issues)} issue(s)).",
            f"- Conservative unresolved-case warnings: {len(validation_warnings)}.",
        ]
    )
    if validation_issues:
        lines.extend(["", "Validator issues (first 30):", ""])
        lines.extend(f"- {issue}" for issue in validation_issues[:30])
    if validation_warnings:
        lines.extend(
            [
                "",
                "Unresolved cases kept `INCOMPLETE` because available evidence does not support a "
                "subject-specific finding or complete remediation plan (first 30):",
                "",
            ]
        )
        lines.extend(f"- {warning}" for warning in validation_warnings[:30])
    lines.extend(
        [
            "",
            "## Additional automated evaluation cases",
            "",
            "The independent `unittest` suite creates its own synthetic evidence rather than "
            "using any public or hidden expected rows:",
            "",
            "1. Non-deletion request returns `NOT_APPLICABLE` with an empty array.",
            "2. A remaining profile triggers finding, delete remediation, and future verification.",
            "3. Evidence captured after `audit_at` is ignored.",
            "4. An absence observation before the request cannot prove deletion complete.",
            "5. A post-request account-absence observation supports an evidence-backed completion.",
            "6. A historical email alias resolves to its stable user.",
            "7. An active data flow triggers disable and verify-disabled actions.",
            "8. An active restore path triggers block and verify-blocked actions.",
            "9. A policy-retained security record is not deleted.",
            "10. A shared support message with identifiers is redacted, not deleted.",
            "11. Identifiable analytics is anonymized.",
            "12. Duplicate evidence for one resource does not duplicate remediation.",
            "13. An identifying tombstone is redacted while retaining its stable reference.",
            "",
            f"Custom test result: {test_result}.",
            "",
            "## Failures found and improvements made",
            "",
            "- Replaced whole-file identity matching with record-scoped structured evidence; log records "
            "are correlated only within a trace identifier, and PDF records are segmented by record blocks.",
            "- Added historical aliases, stable user references, email hashes and phone identifiers; "
            "identity audit values are now time-bounded by the case cutoff.",
            "- Added SQLite snapshot, JSON, log/text, PDF and activity-resource association handling. "
            "Activity result fields are not used as proof of final record state.",
            "- Enforced evidence capture/record timestamps at or before `audit_at`, rule-directed "
            "redaction/anonymization/retention, future-step empty evidence IDs and phase/operation ordering.",
            "- The sample comparison still exposes material gaps. In particular, resource-to-subject "
            "linkage for negative lookups cannot be invented when no pre-cutoff record ties the resource "
            "to the subject, and PNG screenshots are not OCR-processed.",
            "- COMPLETE is withheld when no evidence-backed absent primary profile is found; such cases "
            "remain `INCOMPLETE` with no fabricated finding or resource ID. This conservative uncertainty "
            "is surfaced rather than represented as proof.",
            "",
            "## Scope and limitations",
            "",
            "The measured public sample is a validation set, not evidence of hidden-test accuracy. "
            "No organizer-only files or expected labels were used to make predictions. The 11 PNG "
            "artifacts in the manifest are currently not interpreted; OCR would be needed to cover "
            "image-only facts. Text extracted from PDFs and all other supported sources is subject to "
            "the same per-case temporal and identity matching rules.",
            "",
        ]
    )
    EVALUATION_REPORT.write_text("\n".join(lines), encoding="utf-8")


def build_usage_report():
    output_rows, _ = read_csv(OUTPUT)
    status_counts = Counter(row["deletion_status"] for row in output_rows)
    content = [
        "# Usage Report",
        "",
        "## Full-dataset run",
        "",
        f"- Output generated/reported at: `{datetime.now(timezone.utc).isoformat()}`.",
        "- Processing: local deterministic Python; no hosted model API or external inference service.",
        "- Model provider: none.",
        "- Model name: none (no model was called).",
        "- External model calls: **0**.",
        "- Model-token usage: **0 input tokens, 0 output tokens, 0 total tokens; average 0 tokens per request**.",
        "- Estimated model cost: **$0.00 total and $0.00 per request**.",
        f"- Requests processed in the current root output: **{len(output_rows)}**.",
        f"- Output status totals: `{dict(sorted(status_counts.items()))}`.",
        "- Per-model totals: none (there are no model calls); overall input/output/total tokens are "
        "**0/0/0** and overall estimated cost is **$0.00**.",
        "",
        "The input dataset and local evidence parsing do not generate model tokens. These figures "
        "report actual external model usage, not an estimate of local CPU work.",
        "",
    ]
    USAGE_REPORT.write_text("\n".join(content), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description="Validate and evaluate Ghost Data Still Exists output")
    parser.add_argument(
        "command",
        choices=("validate", "compare", "report"),
        nargs="?",
        default="validate",
    )
    args = parser.parse_args()
    if args.command == "validate":
        issues, summary = validate_output()
        print(
            f"rows={summary['rows']} header_ok={summary['header_ok']} "
            f"structural_issues={len(issues)} semantic_warnings={len(summary.get('semantic_warnings', []))}"
        )
        for issue in issues:
            print(f"FAIL: {issue}")
        if issues:
            raise SystemExit(1)
        print("PASS: root output satisfies structural and evidence-reference checks")
        for warning in summary.get("semantic_warnings", []):
            print(f"WARNING: {warning}")
        return
    requests, expected, actual, manifest = predict_public_samples()
    metrics = score_public_samples(requests, expected, actual)
    print(
        "samples={case_count} status={status_correct}/{case_count} "
        "exact={exact_correct}/{case_count} sequence={sequence_correct}/{case_count} "
        "step_precision={step_precision:.4f} step_recall={step_recall:.4f} "
        "step_f1={step_f1:.4f} field_accuracy={field_accuracy:.4f} "
        "evidence_mismatches={evidence_mismatches} missing={missing_steps} extra={extra_steps}".format(
            **metrics
        )
    )
    if args.command == "report":
        issues, validation_summary = validate_output()
        test_run = subprocess.run(
            [
                sys.executable,
                "-m",
                "unittest",
                "discover",
                "-s",
                str(EVALUATION_DIR),
                "-v",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        test_output = test_run.stdout + test_run.stderr
        test_summary = re.search(r"Ran (\d+) tests? in ([\d.]+)s", test_output)
        if test_run.returncode == 0 and test_summary:
            tests = f"PASS: {test_summary.group(1)} tests in {test_summary.group(2)}s"
        else:
            tests = "FAIL: " + " ".join(test_output.split())
        build_evaluation_report(
            requests,
            expected,
            actual,
            manifest,
            metrics,
            issues,
            validation_summary.get("semantic_warnings", []),
            tests,
        )
        build_usage_report()
        print(f"Wrote {EVALUATION_REPORT} and {USAGE_REPORT}")
        if test_run.returncode:
            raise SystemExit(test_run.returncode)


if __name__ == "__main__":
    main()
