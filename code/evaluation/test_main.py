import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

CODE_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CODE_DIR))

import main


AUDIT_AT = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
USER_ID = "user_7"
EMAIL = "current@example.test"


def evidence(
    resource_id,
    category,
    state,
    *,
    pii=False,
    email=EMAIL,
    evidence_id="evidence_test",
    captured_at=AUDIT_AT,
):
    return main.Evidence(
        resource_id=resource_id,
        system_id=main.infer_system(category, (), resource_id),
        category=category,
        state=state,
        pii_present=pii,
        captured_at=captured_at,
        evidence_id=evidence_id,
        fields=(),
        source_values=(USER_ID, email),
        source_kind="test",
        observed_at=captured_at,
    )


def run_case(
    catalog,
    *,
    text="Please delete my account.",
    email=EMAIL,
    user_id=USER_ID,
    audit_rows=None,
    requested_at="2026-09-10T12:00:00Z",
):
    email_to_users = {email: {user_id}, "old@example.test": {user_id}}
    identifiers_by_user = {user_id: {user_id}}
    current_rows = {
        user_id: {
            "user_id": user_id,
            "email": EMAIL,
            "email_hash": "",
            "phone": "",
            "updated_at": "2026-01-01T00:00:00Z",
        }
    }
    request = {
        "case_id": "case_test",
        "email": email,
        "requested_at": requested_at,
        "audit_at": AUDIT_AT.isoformat(),
        "request_text": text,
    }
    return main.build_result(
        request,
        email_to_users,
        identifiers_by_user,
        current_rows,
        audit_rows or [],
        catalog,
        main.load_rules(),
    )


class DeletionAuditTests(unittest.TestCase):
    def test_non_deletion_request_is_not_applicable(self):
        status, steps = run_case(
            [], text="Please keep my account and do not delete or erase anything."
        )
        self.assertEqual(status, "NOT_APPLICABLE")
        self.assertEqual(steps, [])

    def test_remaining_record_requires_delete_and_future_verification(self):
        status, steps = run_case([evidence("account_7", "USER_PROFILE", "present", pii=True)])
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(
            [step["operation"] for step in steps],
            ["REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"],
        )
        self.assertEqual(steps[0]["evidence_id"], "evidence_test")
        self.assertTrue(all(step["evidence_id"] == "" for step in steps[1:]))

    def test_evidence_after_audit_cutoff_is_ignored(self):
        later = datetime(2026, 9, 16, 12, 0, tzinfo=timezone.utc)
        status, steps = run_case(
            [
                evidence(
                    "account_7",
                    "USER_PROFILE",
                    "present",
                    pii=True,
                    captured_at=later,
                )
            ]
        )
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(steps, [])

    def test_absence_before_request_does_not_prove_deletion_complete(self):
        before_request = datetime(2026, 9, 9, 12, 0, tzinfo=timezone.utc)
        status, steps = run_case(
            [
                evidence(
                    "account_7",
                    "USER_PROFILE",
                    "absent",
                    evidence_id="evidence_old",
                    captured_at=before_request,
                )
            ]
        )
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(steps, [])

    def test_post_request_absence_is_evidence_backed_complete(self):
        status, steps = run_case(
            [evidence("account_7", "USER_PROFILE", "absent", evidence_id="evidence_current")]
        )
        self.assertEqual(status, "COMPLETE")
        self.assertEqual([step["operation"] for step in steps], ["VERIFY_RECORD_ABSENT"])
        self.assertEqual(steps[0]["evidence_id"], "evidence_current")

    def test_historical_email_resolves_to_same_subject(self):
        historical = evidence(
            "search_9",
            "SEARCH_INDEX_ENTRY",
            "present",
            email="old@example.test",
        )
        status, steps = run_case(
            [historical],
            email="old@example.test",
            audit_rows=[
                {
                    "user_id": USER_ID,
                    "event_time": "2026-02-01T00:00:00Z",
                    "old_value": "old@example.test",
                    "new_value": EMAIL,
                }
            ],
        )
        self.assertEqual(status, "INCOMPLETE")
        self.assertIn("search_9", [step["resource_id"] for step in steps])

    def test_active_data_flow_requires_disable_and_verification(self):
        status, steps = run_case([evidence("data_flow_9", "DATA_FLOW", "active")])
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(
            [step["operation"] for step in steps],
            [
                "REPORT_ACTIVE_DATA_FLOW",
                "DISABLE_DATA_FLOW",
                "VERIFY_DATA_FLOW_DISABLED",
            ],
        )

    def test_restore_risk_requires_blocking(self):
        status, steps = run_case([evidence("backup_9", "BACKUP_ARCHIVE", "active")])
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(
            [step["operation"] for step in steps],
            ["REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"],
        )

    def test_policy_retained_audit_record_is_verified_present(self):
        observation = evidence("audit_record_9", "SECURITY_AUDIT_LOG", "present")
        result = main.desired_state(observation, main.load_rules())
        self.assertEqual(result[0], "compliant")
        self.assertEqual(result[3], "VERIFY_RECORD_PRESENT")
        status, steps = run_case([observation])
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(steps, [])

    def test_support_message_with_identifiers_is_redacted_not_deleted(self):
        status, steps = run_case(
            [evidence("support_9", "SUPPORT_MESSAGE", "present", pii=True)]
        )
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(
            [step["operation"] for step in steps],
            ["REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"],
        )

    def test_identifiable_analytics_is_anonymized(self):
        status, steps = run_case(
            [evidence("analytics_9", "ANALYTICS_PROFILE", "present", pii=True)]
        )
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(
            [step["operation"] for step in steps],
            ["REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"],
        )

    def test_duplicate_copies_of_same_resource_emit_one_remediation(self):
        status, steps = run_case(
            [
                evidence("search_9", "SEARCH_INDEX_ENTRY", "present", evidence_id="evidence_a"),
                evidence("search_9", "SEARCH_INDEX_ENTRY", "present", evidence_id="evidence_b"),
            ]
        )
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(
            [step["operation"] for step in steps],
            ["REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"],
        )

    def test_tombstone_with_personal_fields_is_redacted(self):
        status, steps = run_case(
            [evidence("tombstone_9", "ACCOUNT_TOMBSTONE", "present", pii=True)]
        )
        self.assertEqual(status, "INCOMPLETE")
        self.assertEqual(
            [step["operation"] for step in steps],
            ["REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"],
        )


if __name__ == "__main__":
    unittest.main()
