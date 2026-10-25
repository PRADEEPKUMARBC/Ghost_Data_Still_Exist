import csv
import json
import re
import sqlite3
import sys
import unicodedata
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "dataset"
OUTPUT = ROOT / "output.csv"

EVIDENCE_FILES = DATASET / "evidence_files.csv"
REQUESTS = DATASET / "deletion_requests.csv"
IDENTITIES = DATASET / "user_identities.csv"
AUDIT_LOG = DATASET / "user_audit_log.csv"
ACTIVITY = DATASET / "system_activity.csv"
RULES = DATASET / "deletion_rules.csv"

STEP_FIELDS = {
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 0,
    "REPORT_EXPOSED_PII": 1,
    "REPORT_ACTIVE_DATA_FLOW": 2,
    "REPORT_RESTORE_RISK": 3,
    "DISABLE_DATA_FLOW": 4,
    "BLOCK_RESTORE": 5,
    "DELETE_RECORD": 6,
    "REDACT_RECORD": 7,
    "ANONYMIZE_RECORD": 8,
    "VERIFY_RECORD_ABSENT": 9,
    "VERIFY_RECORD_PRESENT": 10,
    "VERIFY_RECORD_REDACTED": 11,
    "VERIFY_RECORD_ANONYMIZED": 12,
    "VERIFY_DATA_FLOW_DISABLED": 13,
    "VERIFY_RESTORE_BLOCKED": 14,
}
ALLOWED_PHASES = set(PHASE_ORDER)
ALLOWED_OPERATIONS = set(OPERATION_ORDER)
OPERATION_STATES = {
    "REPORT_REMAINING_RECORD": ("FINDING", "PRESENT"),
    "REPORT_EXPOSED_PII": ("FINDING", "PRESENT"),
    "REPORT_ACTIVE_DATA_FLOW": ("FINDING", "ACTIVE"),
    "REPORT_RESTORE_RISK": ("FINDING", "ACTIVE"),
    "DELETE_RECORD": ("REMEDIATION", "ABSENT"),
    "REDACT_RECORD": ("REMEDIATION", "REDACTED"),
    "ANONYMIZE_RECORD": ("REMEDIATION", "ANONYMIZED"),
    "DISABLE_DATA_FLOW": ("REMEDIATION", "DISABLED"),
    "BLOCK_RESTORE": ("REMEDIATION", "BLOCKED"),
    "VERIFY_RECORD_ABSENT": ("VERIFICATION", "ABSENT"),
    "VERIFY_RECORD_PRESENT": ("VERIFICATION", "PRESENT"),
    "VERIFY_RECORD_REDACTED": ("VERIFICATION", "REDACTED"),
    "VERIFY_RECORD_ANONYMIZED": ("VERIFICATION", "ANONYMIZED"),
    "VERIFY_DATA_FLOW_DISABLED": ("VERIFICATION", "DISABLED"),
    "VERIFY_RESTORE_BLOCKED": ("VERIFICATION", "BLOCKED"),
}

RESOURCE_RE = re.compile(
    r"\b(account|search|support|export|analytics|data_flow|backup|"
    r"audit_record|tombstone|cache|marketing|delivery_log)_\d+\b",
    re.IGNORECASE,
)
DATE_RE = re.compile(r"^\s*(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z?)")
EMAIL_RE = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)
USER_ID_RE = re.compile(r"\buser_\d+\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE)
NEGATIVE_REQUEST_RE = re.compile(
    r"\b(?:"
    r"do not (?:delete|erase|remove|close)|don't (?:delete|erase|remove|close)|"
    r"did not (?:request|ask for) (?:a )?(?:deletion|erasure)|"
    r"not (?:requesting|asking for) (?:a )?(?:deletion|erasure)|"
    r"without (?:deleting|erasing|closing)|keep (?:my|the) (?:account|data|profile)|"
    r"leave (?:my|the) (?:account|data|profile)|"
    r"no (?:deletion|erasure)|cancel (?:my )?(?:deletion|erasure) request|"
    r"ne supprimez pas|ne supprime pas|no elimines|no elimine|"
    r"no borres|no borre|nicht löschen|nicht loeschen|"
    r"削除しない|削除しないで"
    r")\b",
    re.IGNORECASE,
)
POSITIVE_REQUEST_RE = re.compile(
    r"\b(?:delet\w*|eras\w*|remov\w*|clos\w*|forget\w*|"
    r"right to be forgotten|data subject request|"
    r"supprim\w*|suppression|effac\w*|elimin\w*|exclu\w*|"
    r"losch\w*|entfern\w*)\b|削除|消去",
    re.IGNORECASE,
)
VERIFICATION_REQUEST_RE = re.compile(
    r"\b(?:audit|verify|check|confirm|review)\w*\b.{0,100}"
    r"\b(?:account|profile|data|personal details|email|gone|removed|deleted|"
    r"retained|identify|identified)\b|"
    r"\b(?:account|profile|data|personal details)\b.{0,100}"
    r"\b(?:gone|removed|deleted|retained|identify|identified)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Evidence:
    resource_id: str
    system_id: str
    category: str
    state: str
    pii_present: bool
    captured_at: datetime
    evidence_id: str
    fields: tuple
    source_values: tuple
    source_kind: str
    observed_at: datetime


def parse_iso(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def norm(value):
    return unicodedata.normalize("NFKC", str(value or "")).strip().casefold()


def digits(value):
    return "".join(re.findall(r"\d", str(value or "")))


def normalized_text(value):
    value = unicodedata.normalize("NFKD", str(value or ""))
    return "".join(char for char in value if not unicodedata.combining(char)).casefold()


def authorizes_deletion(request_text):
    text = normalized_text(request_text)
    if NEGATIVE_REQUEST_RE.search(text):
        return False
    return bool(POSITIVE_REQUEST_RE.search(text) or VERIFICATION_REQUEST_RE.search(text))


def read_csv(path):
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def load_manifest():
    manifest = {}
    for row in read_csv(EVIDENCE_FILES):
        manifest[row["file_id"]] = row
    return manifest


@lru_cache(maxsize=1)
def load_activity_rows():
    return tuple(read_csv(ACTIVITY))


@lru_cache(maxsize=512)
def identifier_lookup(values):
    normalized = frozenset(norm(value) for value in values if norm(value))
    numeric = frozenset(
        digits(value) for value in normalized if "@" not in value and len(digits(value)) >= 7
    )
    return normalized, numeric


def load_identity_data():
    email_to_users = defaultdict(set)
    identifiers_by_user = defaultdict(set)
    current_rows = {}
    audit_rows = read_csv(AUDIT_LOG)
    for row in read_csv(IDENTITIES):
        user_id = norm(row["user_id"])
        identifiers_by_user[user_id].add(user_id)
        current_rows[user_id] = row
        for field in ("email", "email_hash", "phone"):
            value = norm(row.get(field))
            if value:
                identifiers_by_user[user_id].add(value)
        email = norm(row.get("email"))
        if email:
            email_to_users[email].add(user_id)
    for row in audit_rows:
        user_id = norm(row["user_id"])
        for field in ("old_value", "new_value"):
            value = norm(row.get(field))
            if value and "@" in value:
                email_to_users[value].add(user_id)
    return email_to_users, identifiers_by_user, current_rows, audit_rows


def load_user_map():
    email_to_users, identifiers_by_user, _, _ = load_identity_data()
    email_to_user = {
        email: next(iter(users)) for email, users in email_to_users.items() if len(users) == 1
    }
    emails_by_user = defaultdict(set)
    for email, users in email_to_users.items():
        if len(users) == 1:
            emails_by_user[next(iter(users))].add(email)
    for user_id, identifiers in identifiers_by_user.items():
        emails_by_user[user_id].update(value for value in identifiers if "@" in value)
    return email_to_user, emails_by_user


def identity_identifiers(user_id, request_email, audit_at, email_to_users, identifiers_by_user, current_rows, audit_rows):
    values = {user_id}
    if request_email:
        values.add(norm(request_email))
    current = current_rows.get(user_id)
    if current:
        updated_at = parse_iso(current.get("updated_at"))
        if updated_at is None or updated_at <= audit_at:
            for field in ("email", "email_hash", "phone"):
                value = norm(current.get(field))
                if value:
                    values.add(value)
    for row in audit_rows:
        if norm(row["user_id"]) != user_id:
            continue
        event_time = parse_iso(row.get("event_time"))
        if event_time and event_time <= audit_at:
            for field in ("old_value", "new_value"):
                value = norm(row.get(field))
                if value:
                    values.add(value)
    return values


def identity_matches(values, identifiers):
    normalized_identifiers, numeric_identifiers = identifier_lookup(
        tuple(sorted(norm(value) for value in identifiers if norm(value)))
    )
    for value in values:
        normalized = norm(value)
        if not normalized:
            continue
        if normalized in normalized_identifiers:
            return True
        if "@" not in normalized and len(digits(normalized)) >= 7:
            if digits(normalized) in numeric_identifiers:
                return True
    return False


def flatten_record(record):
    values = []

    def collect(value):
        if isinstance(value, dict):
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)
        elif value is not None:
            values.append(str(value))

    collect(record)
    return values


def direct_values(record):
    values = []
    if isinstance(record, dict):
        for key, value in record.items():
            if isinstance(value, (dict, list)):
                continue
            if value is not None:
                values.append((norm(key), str(value)))
    return values


def infer_system(category, context, resource_id):
    context_text = " ".join(str(item) for item in context if item).casefold()
    rid = resource_id.casefold()
    resource_prefixes = (
        ("account_", "account_service"),
        ("search_", "search_service"),
        ("support_", "support_platform"),
        ("export_", "export_service"),
        ("analytics_", "analytics_platform"),
        ("data_flow_", "integration_service"),
        ("backup_", "backup_service"),
        ("audit_record_", "security_service"),
        ("tombstone_", "identity_service"),
        ("cache_", "cache_service"),
        ("marketing_", "marketing_service"),
        ("delivery_log_", "notification_service"),
    )
    for prefix, system_id in resource_prefixes:
        if rid.startswith(prefix):
            return system_id
    explicit = {
        "account_service": "account_service",
        "search_service": "search_service",
        "support_platform": "support_platform",
        "export_service": "export_service",
        "analytics_platform": "analytics_platform",
        "integration_service": "integration_service",
        "backup_service": "backup_service",
        "security_service": "security_service",
        "marketing_service": "marketing_service",
        "cache_service": "cache_service",
        "notification_service": "notification_service",
    }
    for system, system_id in explicit.items():
        if system in context_text:
            return system_id
    if category in {"USER_PROFILE", "ACCOUNT_TOMBSTONE", "SECONDARY_IDENTIFIER"}:
        return "account_service" if category != "ACCOUNT_TOMBSTONE" else "identity_service"
    if category in {"SEARCH_INDEX_ENTRY"} or rid.startswith("search_"):
        return "search_service"
    if category in {"SUPPORT_MESSAGE", "SUPPORT_ATTACHMENT"} or rid.startswith("support_"):
        return "support_platform"
    if category in {"USER_EXPORT"} or rid.startswith("export_"):
        return "export_service"
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"} or rid.startswith("analytics_"):
        return "analytics_platform"
    if category == "DATA_FLOW" or rid.startswith("data_flow_"):
        return "integration_service"
    if category == "BACKUP_ARCHIVE" or rid.startswith("backup_"):
        return "backup_service"
    if category in {"SECURITY_AUDIT_LOG"} or rid.startswith("audit_record_"):
        return "security_service"
    if category == "MARKETING_PROFILE" or rid.startswith("marketing_"):
        return "marketing_service"
    if category == "CACHE_ENTRY" or rid.startswith("cache_"):
        return "cache_service"
    if category == "EMAIL_DELIVERY_LOG" or rid.startswith("delivery_log_"):
        return "notification_service"
    return "unknown"


def infer_category(context, record, resource_id):
    explicit = []
    for key in ("record_type", "data_category", "category", "collection", "table", "recordType"):
        value = record.get(key) if isinstance(record, dict) else None
        if value:
            explicit.append(str(value))
    explicit.extend(str(item) for item in context if item)
    event = str(record.get("event", record.get("event_type", ""))).upper().replace("-", "_")
    if "CONTACT_LOOKUP" in event or "IDENTIFIER_LOOKUP" in event:
        return "SECONDARY_IDENTIFIER"
    text = " ".join(explicit).upper().replace("-", "_")
    rid = resource_id.casefold()
    if "TOMBSTONE" in text or rid.startswith("tombstone_"):
        return "ACCOUNT_TOMBSTONE"
    if "ATTACHMENT" in text:
        return "SUPPORT_ATTACHMENT"
    if "SUPPORT" in text or rid.startswith("support_"):
        return "SUPPORT_MESSAGE"
    if "SEARCH" in text or rid.startswith("search_"):
        return "SEARCH_INDEX_ENTRY"
    if "EXPORT" in text or rid.startswith("export_"):
        return "USER_EXPORT"
    if "ANALYTIC" in text or rid.startswith("analytics_"):
        return "ANALYTICS_PROFILE"
    if "TELEMETRY" in text:
        return "PRODUCT_TELEMETRY"
    if "CONNECTOR" in text or "DATA_FLOW" in text or rid.startswith("data_flow_"):
        return "DATA_FLOW"
    if "BACKUP" in text or rid.startswith("backup_"):
        return "BACKUP_ARCHIVE"
    if "AUDIT" in text or rid.startswith("audit_record_"):
        return "SECURITY_AUDIT_LOG"
    if "MARKETING" in text or rid.startswith("marketing_"):
        return "MARKETING_PROFILE"
    if "CACHE" in text or rid.startswith("cache_"):
        return "CACHE_ENTRY"
    if "DELIVERY" in text or "EMAIL" in text and "LOG" in text:
        return "EMAIL_DELIVERY_LOG"
    if "PROFILE" in text or rid.startswith("account_"):
        return "USER_PROFILE"
    return "SECONDARY_IDENTIFIER"


def record_state(record, category, direct, text):
    string_values = [value.casefold() for _, value in direct]
    combined = " ".join(
        string_values
        + [f"{key}={value}".casefold() for key, value in direct]
        + [text.casefold()]
    )
    key_values = {key: value.casefold() for key, value in direct}
    pii_keys = ("email", "phone", "full_name", "requester_name", "display_name", "email_hash", "phone_hash")
    pii_present = any(
        value.strip() and value.strip().casefold() not in {"null", "none", "false", "n/a"}
        for key, value in direct
        if key in pii_keys
        or (
            key.startswith(("email_", "phone_"))
            or key.endswith(("_email", "_phone", "_name", "_email_hash", "_phone_hash"))
            and not key.startswith(("event_", "record_"))
        )
    )
    if "identifiable" in combined or "matched_value=" in combined:
        pii_present = True
    if category == "DATA_FLOW":
        if any(term in combined for term in ("enabled=false", "enabled: false", "disabled", "stopped", "inactive")):
            return "disabled", False
        if any(term in combined for term in ("enabled=true", "enabled: true", "active", "registered")):
            return "active", pii_present
        return "unknown", pii_present
    if category == "BACKUP_ARCHIVE":
        if "eligible=true" in combined and "deletion_block=false" in combined:
            return "active", pii_present
        if "deletion_block=true" in combined:
            return "blocked", pii_present
        if any(term in combined for term in ("restore_allowed=0", "restore_allowed: 0", "restore_allowed=false", "blocked", "restore access blocked")):
            return "blocked", pii_present
        if any(term in combined for term in ("restore_allowed=1", "restore_allowed: 1", "restore_allowed=true", "restore access", "active")):
            return "active", pii_present
        return "unknown", pii_present
    if category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"}:
        return "present", pii_present
    if any(term in combined for term in ("not_found", "not found", "404", "rows=0", "rows: 0", "profile\": null", "profile': none")):
        return "absent", False
    if any(term in combined for term in ("anonymized", "anonymous", "irreversibly_unlinked")):
        return "anonymized", pii_present
    if category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"} and not pii_present:
        return "anonymized", False
    if any(term in combined for term in ("redacted", "redaction_complete")):
        return "redacted", pii_present
    if any(term in combined for term in ("deleted", "absent")) and category not in {"ACCOUNT_TOMBSTONE"}:
        return "absent", False
    if any(value in {"identifiable", "found", "hit", "present", "active", "deletion_pending"} for value in string_values):
        return "present", pii_present
    return "present", pii_present


def make_evidence(
    resource_id,
    context,
    record,
    file_id,
    captured_at,
    source_kind,
    source_values=(),
):
    direct = direct_values(record)
    text = " ".join(flatten_record(record))
    category = infer_category(context, record, resource_id)
    system_id = infer_system(category, context, resource_id)
    state, pii_present = record_state(record, category, direct, text)
    row_times = []
    for key, value in direct:
        if key in {"updated_at", "observed_at", "recorded_at", "event_time", "captured_at"}:
            timestamp = parse_iso(value)
            if timestamp:
                row_times.append(timestamp)
    observed_at = max(row_times) if row_times else captured_at
    return Evidence(
        resource_id=resource_id,
        system_id=system_id,
        category=category,
        state=state,
        pii_present=pii_present,
        captured_at=captured_at,
        evidence_id=file_id,
        fields=tuple(sorted(direct)),
        source_values=tuple(source_values or flatten_record(record)),
        source_kind=source_kind,
        observed_at=observed_at,
    )


def json_records(value, context=()):
    if isinstance(value, dict):
        next_context = list(context)
        for key in ("system", "system_id", "data_store", "collection", "record_type", "data_category", "table"):
            if value.get(key):
                next_context.append(str(value[key]))
        resource_id = value.get("resource_id") or value.get("resourceId")
        if resource_id:
            yield str(resource_id), tuple(next_context), value
        for key, child in value.items():
            if key in {"resource_id", "resourceId"}:
                continue
            yield from json_records(child, tuple(next_context))
    elif isinstance(value, list):
        for child in value:
            yield from json_records(child, context)


def sql_records(path):
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(path.read_text(encoding="utf-8-sig", errors="replace"))
        tables = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        ).fetchall()
        for (table_name,) in tables:
            columns = connection.execute(f'PRAGMA table_info("{table_name}")').fetchall()
            names = [column[1] for column in columns]
            if "resource_id" not in names:
                continue
            query = f'SELECT * FROM "{table_name}"'
            for row in connection.execute(query):
                record = dict(zip(names, row))
                yield str(record["resource_id"]), (table_name,), record
    except sqlite3.Error as error:
        raise RuntimeError(f"Unable to parse SQL evidence {path}") from error
    finally:
        connection.close()


def parse_key_values(line):
    values = {}
    for match in re.finditer(r"([\w.-]+)=([^ ]+(?: [^= ]+)?)(?=\s+[\w.-]+=|$)", line):
        values[match.group(1)] = match.group(2).strip().strip("\"'")
    return values


def parse_text_records(text):
    lines = text.splitlines()
    parsed = []
    for line in lines:
        resources = [match.group(0) for match in RESOURCE_RE.finditer(line)]
        timestamp_match = DATE_RE.match(line)
        timestamp = timestamp_match.group(1) if timestamp_match else None
        record = parse_key_values(line)
        if resources:
            pipe_parts = [part.strip() for part in line.split("|")]
            if len(pipe_parts) >= 5:
                record.update(
                    {
                        "resource_id": resources[0],
                        "system": pipe_parts[-5] if len(pipe_parts) > 5 else pipe_parts[-4],
                        "record_type": pipe_parts[-3],
                        "result": pipe_parts[-2],
                    }
                )
                if len(pipe_parts) > 5:
                    record["subject_reference"] = pipe_parts[-1]
            else:
                record["resource_id"] = resources[0]
        if timestamp:
            record["observed_at"] = timestamp
        parsed.append((line, resources, record, timestamp))
    return parsed


def pdf_text(path):
    from pypdf import PdfReader

    return "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)


def read_evidence_content(path):
    suffix = path.suffix.casefold()
    if suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8-sig"))
    if suffix == ".sql":
        return None
    if suffix == ".pdf":
        return pdf_text(path)
    if suffix == ".png":
        return None
    return path.read_text(encoding="utf-8-sig", errors="replace")


def parse_pdf_records(text, path):
    blocks = re.split(r"(?im)(?=^Record\s*$)", text)
    for block in blocks:
        resources = [match.group(0) for match in RESOURCE_RE.finditer(block)]
        if not resources:
            continue
        record = {"raw_text": block}
        for index, email in enumerate(EMAIL_RE.findall(block)):
            record[f"email_{index}"] = email
        user_refs = re.findall(r"\buser_\d+\b", block, re.IGNORECASE)
        for index, user_id in enumerate(user_refs):
            record[f"subject_reference_{index}"] = user_id
        phones = re.findall(r"\+\d[\d ()-]{7,}\d", block)
        for index, phone in enumerate(phones):
            record[f"phone_{index}"] = phone
        for resource_id in set(resources):
            record["resource_id"] = resource_id
            yield resource_id, (path.stem, block[:160]), record


def build_evidence_catalog(manifest):
    observations = []
    unsupported_images = []
    for file_id, entry in manifest.items():
        captured_at = parse_iso(entry.get("captured_at"))
        if not captured_at:
            continue
        path = DATASET / entry["file_path"]
        if not path.is_file():
            raise FileNotFoundError(f"Evidence file {file_id} is missing: {path}")
        suffix = path.suffix.casefold()
        try:
            if suffix == ".sql":
                records = sql_records(path)
                for resource_id, context, record in records:
                    evidence = make_evidence(
                        resource_id, context, record, file_id, captured_at, "sql"
                    )
                    if evidence:
                        observations.append(evidence)
                continue
            content = read_evidence_content(path)
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise RuntimeError(f"Unable to read evidence {file_id}: {path}") from error
        if suffix == ".png":
            unsupported_images.append(file_id)
            continue
        if isinstance(content, dict) or isinstance(content, list):
            for resource_id, context, record in json_records(content):
                evidence = make_evidence(
                    resource_id, context, record, file_id, captured_at, "json"
                )
                if evidence:
                    observations.append(evidence)
            continue
        text = str(content)
        if suffix == ".pdf":
            for resource_id, context, record in parse_pdf_records(text, path):
                evidence = make_evidence(
                    resource_id,
                    context,
                    record,
                    file_id,
                    captured_at,
                    "pdf",
                )
                if evidence:
                    observations.append(evidence)
            continue
        else:
            parsed_records = parse_text_records(text)
        groups = defaultdict(list)
        for line, resource_ids, record, timestamp in parsed_records:
            trace = re.search(r"(?:trace_id|trace)=([\w-]+)", line, re.IGNORECASE)
            key = trace.group(1) if trace else f"line:{len(groups)}:{line[:60]}"
            groups[key].append((line, resource_ids, record, timestamp))
        for records in groups.values():
            correlated_values = [
                value
                for line, _, record, _ in records
                for value in [line, *flatten_record(record)]
            ]
            for line, _, _, _ in records:
                correlated_values.extend(EMAIL_RE.findall(line))
                correlated_values.extend(USER_ID_RE.findall(line))
                correlated_values.extend(HASH_RE.findall(line))
                correlated_values.extend(re.findall(r"\+\d[\d ()-]{7,}\d", line))
            for line, resource_ids, record, timestamp in records:
                for resource_id in resource_ids:
                    context = (path.stem, str(record.get("record_type", "")),)
                    evidence = make_evidence(
                        resource_id,
                        context,
                        record,
                        file_id,
                        captured_at,
                        suffix.lstrip("."),
                        correlated_values,
                    )
                    if evidence:
                        observations.append(evidence)
    return observations, unsupported_images


def collect_evidence(catalog, identifiers, audit_at):
    resource_hints = collect_activity_hints(identifiers, audit_at)
    hinted_resources = {hint[0] for hint in resource_hints}
    eligible = [
        observation
        for observation in catalog
        if observation.captured_at <= audit_at
        and observation.observed_at <= audit_at
    ]
    linked_resources = {
        observation.resource_id
        for observation in eligible
        if identity_matches(observation.source_values, identifiers)
    }
    linked_resources.update(hinted_resources)
    return [
        observation
        for observation in eligible
        if observation.resource_id in linked_resources
    ]


def collect_activity_hints(identifiers, audit_at):
    hints = []
    for row in load_activity_rows():
        event_time = parse_iso(row.get("event_time"))
        if not event_time or event_time > audit_at:
            continue
        values = [row.get("resource_id", ""), row.get("details", "")]
        if not identity_matches(values, identifiers):
            continue
        resource_id = row.get("resource_id", "")
        if not resource_id:
            continue
        hints.append((resource_id, row.get("source_system", ""), row.get("target_system", ""), row["activity_id"]))
    return hints


def pick_latest_by_resource(observations):
    latest = {}
    state_priority = {
        "unknown": 0,
        "present": 1,
        "active": 2,
        "redacted": 3,
        "anonymized": 3,
        "disabled": 4,
        "blocked": 4,
        "absent": 5,
    }
    for item in observations:
        current = latest.get(item.resource_id)
        if (
            current is None
            or item.captured_at > current.captured_at
            or (
                item.captured_at == current.captured_at
                and state_priority.get(item.state, 0) > state_priority.get(current.state, 0)
            )
        ):
            latest[item.resource_id] = item
        elif item.captured_at == current.captured_at and item.source_kind == "json" and current.source_kind != "json":
            latest[item.resource_id] = item
    return latest


def desired_state(observation, rules):
    category = observation.category
    required_action = rules.get(category, "")
    if category == "DATA_FLOW":
        if observation.state == "active":
            return "active", "REPORT_ACTIVE_DATA_FLOW", "DISABLE_DATA_FLOW", "VERIFY_DATA_FLOW_DISABLED"
        if observation.state == "disabled":
            return "compliant", None, None, "VERIFY_DATA_FLOW_DISABLED"
        return "unknown", None, None, None
    if category == "BACKUP_ARCHIVE":
        if observation.state == "active":
            return "active", "REPORT_RESTORE_RISK", "BLOCK_RESTORE", "VERIFY_RESTORE_BLOCKED"
        if observation.state == "blocked":
            return "compliant", None, None, "VERIFY_RESTORE_BLOCKED"
        return "unknown", None, None, None
    if category in {"SECURITY_AUDIT_LOG", "LEGAL_HOLD_RECORD"} or required_action == "RETAIN":
        if observation.state in {"present", "active", "redacted"}:
            return "compliant", None, None, "VERIFY_RECORD_PRESENT"
        return "unknown", None, None, None
    if category == "ACCOUNT_TOMBSTONE" or required_action == "REDACT":
        if observation.pii_present:
            return "violation", "REPORT_EXPOSED_PII", "REDACT_RECORD", "VERIFY_RECORD_REDACTED"
        if observation.state in {"redacted", "present"}:
            return "compliant", None, None, "VERIFY_RECORD_REDACTED"
        return "unknown", None, None, None
    if required_action == "ANONYMIZE" or category in {"ANALYTICS_PROFILE", "PRODUCT_TELEMETRY"}:
        if observation.pii_present or observation.state == "present":
            return "violation", "REPORT_EXPOSED_PII", "ANONYMIZE_RECORD", "VERIFY_RECORD_ANONYMIZED"
        if observation.state == "anonymized":
            return "compliant", None, None, "VERIFY_RECORD_ANONYMIZED"
        return "unknown", None, None, None
    if observation.state == "absent":
        return "compliant", None, None, "VERIFY_RECORD_ABSENT"
    if observation.state in {"present", "redacted", "anonymized"}:
        return "violation", "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"
    if required_action in {"DELETE", "DELETE_RECORD"}:
        return "violation", "REPORT_REMAINING_RECORD", "DELETE_RECORD", "VERIFY_RECORD_ABSENT"
    return "unknown", None, None, None


def load_rules():
    return {row["data_category"]: row["required_action"] for row in read_csv(RULES)}


def normalized_step_sort(step):
    return (
        PHASE_ORDER[step["phase"]],
        OPERATION_ORDER[step["operation"]],
        step["system_id"],
        step["resource_id"],
    )


def make_step(step_no, phase, system_id, resource_id, operation, evidence_id=""):
    phase_expected, state = OPERATION_STATES[operation]
    if phase != phase_expected:
        raise ValueError(f"{operation} must be in {phase_expected}")
    return {
        "step_no": step_no,
        "phase": phase,
        "system_id": system_id,
        "resource_id": resource_id,
        "operation": operation,
        "state": state,
        "evidence_id": evidence_id,
    }


def build_result(
    case_row,
    email_to_users,
    identifiers_by_user,
    current_rows,
    audit_rows,
    evidence_catalog,
    rules,
):
    if not authorizes_deletion(case_row.get("request_text", "")):
        return "NOT_APPLICABLE", []
    audit_at = parse_iso(case_row.get("audit_at"))
    if audit_at is None:
        return "INCOMPLETE", []
    email = norm(case_row.get("email"))
    matching_users = email_to_users.get(email, set())
    if len(matching_users) != 1:
        return "INCOMPLETE", []
    user_id = next(iter(matching_users))
    identifiers = identity_identifiers(
        user_id, email, audit_at, email_to_users, identifiers_by_user, current_rows, audit_rows
    )
    observations = collect_evidence(evidence_catalog, identifiers, audit_at)
    latest = pick_latest_by_resource(observations)
    findings = []
    remediation = []
    verification = []
    has_state_evidence = False
    has_unknown_state = False
    account_absent_proven = False
    requested_at = parse_iso(case_row.get("requested_at"))
    if requested_at:
        latest = {
            resource_id: observation
            for resource_id, observation in latest.items()
            if not (
                observation.category == "USER_PROFILE"
                and observation.state == "absent"
                and observation.captured_at < requested_at
            )
        }
    for resource_id, observation in latest.items():
        compliance, finding_operation, remediation_operation, verification_operation = desired_state(
            observation, rules
        )
        if compliance == "unknown" or verification_operation is None:
            has_unknown_state = True
            continue
        has_state_evidence = True
        if (
            observation.category == "USER_PROFILE"
            and observation.state == "absent"
            and requested_at is not None
            and observation.captured_at >= requested_at
        ):
            account_absent_proven = True
        if compliance in {"violation", "active"}:
            findings.append(
                make_step(
                    0,
                    "FINDING",
                    observation.system_id,
                    resource_id,
                    finding_operation,
                    observation.evidence_id,
                )
            )
            remediation.append(
                make_step(
                    0,
                    "REMEDIATION",
                    observation.system_id,
                    resource_id,
                    remediation_operation,
                )
            )
            verification.append(
                make_step(
                    0,
                    "VERIFICATION",
                    observation.system_id,
                    resource_id,
                    verification_operation,
                )
            )
        else:
            verification.append(
                make_step(
                    0,
                    "VERIFICATION",
                    observation.system_id,
                    resource_id,
                    verification_operation,
                    observation.evidence_id,
                )
            )

    if not has_state_evidence:
        return "INCOMPLETE", []

    # A retained audit record alone does not establish deletion completion.
    if (
        not findings
        and not account_absent_proven
                and len(latest) == 1
        and all(
            observation.category == "SECURITY_AUDIT_LOG"
            and observation.state == "present"
            for observation in latest.values()
        )
    ):
        return "INCOMPLETE", []

    steps = findings + remediation + verification
    steps.sort(key=normalized_step_sort)

    # A finding means remediation is still required.
    if findings:
        for step in steps:
            if step["phase"] != "FINDING":
                step["evidence_id"] = ""

    # Missing proof must prevent COMPLETE status, but should not
    # discard verification steps already supported by evidence.
    incomplete = (
        bool(findings)
        or has_unknown_state
        or not account_absent_proven
    )

    for step_no, step in enumerate(steps, start=1):
        step["step_no"] = step_no

    return ("INCOMPLETE" if incomplete else "COMPLETE"), steps


def generate_case_result(case_row, email_to_user, emails_by_user, manifest):
    email_to_users = {email: {user_id} for email, user_id in email_to_user.items()}
    identifiers_by_user = defaultdict(set)
    for user_id, emails in emails_by_user.items():
        identifiers_by_user[user_id].update(emails)
    _, _, current_rows, audit_rows = load_identity_data()
    return build_result(
        case_row,
        email_to_users,
        identifiers_by_user,
        current_rows,
        audit_rows,
        build_evidence_catalog(manifest)[0],
        load_rules(),
    )


def case_sort_key(case_id):
    match = re.search(r"(\d+)$", case_id)
    return (0, int(match.group(1))) if match else (1, case_id)


def main():
    manifest = load_manifest()
    evidence_catalog, unsupported_images = build_evidence_catalog(manifest)
    if unsupported_images:
        print(
            f"Warning: {len(unsupported_images)} PNG evidence files have no OCR extraction; "
            "their contents were not interpreted.",
            file=sys.stderr,
        )
    email_to_users, identifiers_by_user, current_rows, audit_rows = load_identity_data()
    rules = load_rules()
    rows = []
    for case_row in read_csv(REQUESTS):
        status, steps = build_result(
            case_row,
            email_to_users,
            identifiers_by_user,
            current_rows,
            audit_rows,
            evidence_catalog,
            rules,
        )
        rows.append(
            {
                "case_id": case_row["case_id"],
                "deletion_status": status,
                "steps_json": json.dumps(steps, separators=(",", ":"), ensure_ascii=False),
            }
        )
    rows.sort(key=lambda row: case_sort_key(row["case_id"]))
    with OUTPUT.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["case_id", "deletion_status", "steps_json"])
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    main()
