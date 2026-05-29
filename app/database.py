import csv
import os
import re
import shutil
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional

from .security import hash_password

DB_NAME = "lenovo_tracker.db"
STATUS_OPTIONS = ["Ordered", "Pending", "Replaced", "Returned", "Complete"]
PART_OPTIONS = ["Top lid", "Hinges", "Bezel", "LCD", "Keyboard", "Motherboard"]


def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def db_path() -> Path:
    return project_root() / DB_NAME


def backup_dir() -> Path:
    path = project_root() / "backups"
    path.mkdir(exist_ok=True)
    return path


def current_timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def timestamp_for_filename() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def database_url() -> str:
    url = os.environ.get("DATABASE_URL", "").strip()
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    return url


def using_postgres() -> bool:
    return database_url().startswith(("postgresql://", "postgresql+psycopg2://"))


def _convert_placeholders(sql: str) -> str:
    # This app uses SQLite-style ? parameters. psycopg2 expects %s.
    return sql.replace("?", "%s")


class DatabaseConnection:
    def __init__(self):
        self.is_postgres = using_postgres()
        if self.is_postgres:
            import psycopg2
            from psycopg2.extras import RealDictCursor

            url = database_url().replace("postgresql+psycopg2://", "postgresql://", 1)
            self.conn = psycopg2.connect(url, cursor_factory=RealDictCursor)
        else:
            self.conn = sqlite3.connect(db_path())
            self.conn.row_factory = sqlite3.Row

    def execute(self, sql: str, params: tuple | list = ()):
        if self.is_postgres:
            sql = _convert_placeholders(sql)
        cursor = self.conn.cursor()
        cursor.execute(sql, params)
        return cursor

    def commit(self) -> None:
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is None:
            self.conn.commit()
        else:
            self.conn.rollback()
        self.conn.close()


def get_connection() -> DatabaseConnection:
    return DatabaseConnection()


def initialize_database() -> None:
    with get_connection() as conn:
        if conn.is_postgres:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    id SERIAL PRIMARY KEY,
                    work_order TEXT,
                    serial_number TEXT,
                    status TEXT,
                    notes TEXT,
                    timestamp TEXT,
                    followup INTEGER DEFAULT 0,
                    assigned_to TEXT DEFAULT ''
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'tech',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    auth_provider TEXT NOT NULL DEFAULT 'local',
                    email TEXT
                )
                """
            )
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower ON users (lower(email))")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS status_history (
                    id SERIAL PRIMARY KEY,
                    case_id INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
                    old_status TEXT,
                    new_status TEXT NOT NULL,
                    changed_by TEXT,
                    changed_at TEXT NOT NULL,
                    note TEXT
                )
                """
            )
        else:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    work_order TEXT,
                    serial_number TEXT,
                    status TEXT,
                    notes TEXT,
                    timestamp TEXT
                )
                """
            )
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(cases)").fetchall()}
            if "followup" not in columns:
                conn.execute("ALTER TABLE cases ADD COLUMN followup INTEGER DEFAULT 0")
            if "assigned_to" not in columns:
                conn.execute("ALTER TABLE cases ADD COLUMN assigned_to TEXT DEFAULT ''")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    display_name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'tech',
                    is_active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    auth_provider TEXT NOT NULL DEFAULT 'local',
                    email TEXT
                )
                """
            )
            user_columns = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
            if "auth_provider" not in user_columns:
                conn.execute("ALTER TABLE users ADD COLUMN auth_provider TEXT NOT NULL DEFAULT 'local'")
            if "email" not in user_columns:
                conn.execute("ALTER TABLE users ADD COLUMN email TEXT")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS status_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    old_status TEXT,
                    new_status TEXT NOT NULL,
                    changed_by TEXT,
                    changed_at TEXT NOT NULL,
                    note TEXT,
                    FOREIGN KEY(case_id) REFERENCES cases(id)
                )
                """
            )

        user_count = conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        if user_count == 0:
            admin_email = os.environ.get("LCT_ADMIN_EMAIL", "").strip().lower()
            admin_display = os.environ.get("LCT_ADMIN_DISPLAY_NAME", "Tyler Ledbetter").strip() or "Admin"
            local_auth_enabled = os.environ.get("LOCAL_AUTH_ENABLED", "false").strip().lower() == "true"
            admin_username = os.environ.get("LCT_ADMIN_USERNAME", "").strip().lower()
            admin_password = os.environ.get("LCT_ADMIN_PASSWORD", "")
            if admin_email:
                conn.execute(
                    """
                    INSERT INTO users (username, display_name, password_hash, role, is_active, created_at, auth_provider, email)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (admin_email.split("@")[0], admin_display, hash_password(os.urandom(32).hex()), "admin", 1, current_timestamp(), "google", admin_email),
                )
            elif local_auth_enabled and admin_username and admin_password:
                conn.execute(
                    """
                    INSERT INTO users (username, display_name, password_hash, role, is_active, created_at, auth_provider, email)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (admin_username, admin_display, hash_password(admin_password), "admin", 1, current_timestamp(), "local", None),
                )
            else:
                raise RuntimeError(
                    "First-run admin is not configured. Set LCT_ADMIN_EMAIL for Google login, "
                    "or enable LOCAL_AUTH_ENABLED=true and set LCT_ADMIN_USERNAME/LCT_ADMIN_PASSWORD."
                )
        conn.commit()


def build_notes_field(parts: list[str], other: str, notes: str) -> str:
    parts_text = ", ".join(parts) if parts else "None"
    other_text = other.strip() if other.strip() else "None"
    notes_text = notes.strip() if notes.strip() else ""
    return f"Parts: {parts_text} | Other: {other_text} | Notes: {notes_text}"


def parse_notes_field(notes_value: str) -> tuple[list[str], str, str]:
    if not notes_value:
        return [], "", ""
    pattern = r"^Parts:\s*(.*?)\s*\|\s*Other:\s*(.*?)\s*\|\s*Notes:\s*(.*)$"
    match = re.match(pattern, notes_value, re.DOTALL)
    if not match:
        return [], "", notes_value.strip()
    parts_raw = match.group(1).strip()
    other_raw = match.group(2).strip()
    user_notes = match.group(3).strip()
    parts = []
    if parts_raw and parts_raw.lower() != "none":
        parts = [p.strip() for p in parts_raw.split(",") if p.strip()]
    other = "" if other_raw.lower() == "none" else other_raw
    return parts, other, user_notes


def parts_display(notes_value: str) -> str:
    parts, other, _notes = parse_notes_field(notes_value)
    display = list(parts)
    if other:
        display.append(f"Other: {other}")
    return ", ".join(display)


def user_notes_display(notes_value: str) -> str:
    _parts, _other, user_notes = parse_notes_field(notes_value)
    return user_notes


def parse_timestamp(value: str) -> datetime:
    if not value:
        return datetime.max
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    return datetime.max


def build_case_summary(case: dict) -> str:
    parts = case.get("parts", "")
    notes = case.get("user_notes", "")
    lines = [
        f"Work Order: {case.get('work_order', '')}",
        f"Serial Number: {case.get('serial_number', '')}",
        f"Status: {case.get('status', '')}",
        f"Parts: {parts if parts else 'None'}",
        f"Timestamp: {case.get('timestamp', '')}",
    ]
    if case.get("assigned_to"):
        lines.append(f"Assigned To: {case.get('assigned_to')}")
    if case.get("followup"):
        lines.append("Follow-up: Yes")
    if notes:
        lines.append(f"Notes: {notes}")
    return "\n".join(lines)


def row_to_case(row: sqlite3.Row) -> dict:
    data = dict(row)
    notes = data.get("notes") or ""
    case = {
        "id": data.get("id"),
        "work_order": data.get("work_order") or "",
        "serial_number": (data.get("serial_number") or "").upper(),
        "status": data.get("status") or "Ordered",
        "notes": notes,
        "parts": parts_display(notes),
        "user_notes": user_notes_display(notes),
        "timestamp": data.get("timestamp") or "",
        "followup": bool(data.get("followup") or 0),
        "assigned_to": data.get("assigned_to") or "",
    }
    case["summary"] = build_case_summary(case)
    return case


def get_user_by_username(username: str) -> Optional[dict]:
    initialize_database()
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (username.strip().lower(),)).fetchone()
    return dict(row) if row else None


def get_user_by_email(email: str) -> Optional[dict]:
    initialize_database()
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE lower(email) = lower(?) AND is_active = 1", (email.strip(),)).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[dict]:
    initialize_database()
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ? AND is_active = 1", (user_id,)).fetchone()
    return dict(row) if row else None


def list_users() -> list[dict]:
    initialize_database()
    with get_connection() as conn:
        rows = conn.execute("SELECT id, username, display_name, role, is_active, created_at, auth_provider, email FROM users ORDER BY display_name").fetchall()
    return [dict(row) for row in rows]


def create_user(username: str, display_name: str, password: str, role: str = "tech", email: str = "") -> None:
    initialize_database()
    if role not in ("admin", "tech"):
        role = "tech"
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO users (username, display_name, password_hash, role, is_active, created_at, auth_provider, email)
            VALUES (?, ?, ?, ?, 1, ?, 'local', ?)
            """,
            (username.strip().lower(), display_name.strip(), hash_password(password), role, current_timestamp(), email.strip() or None),
        )
        conn.commit()


def create_or_get_oauth_user(email: str, display_name: str) -> Optional[dict]:
    initialize_database()
    email = email.strip().lower()
    existing = get_user_by_email(email)
    if existing:
        return existing

    admin_email = os.environ.get("LCT_ADMIN_EMAIL", "").strip().lower()
    auto_create = os.environ.get("GOOGLE_AUTO_CREATE_USERS", "false").strip().lower() == "true"

    if not auto_create and email != admin_email:
        return None

    username = email.split("@")[0].lower()
    role = "admin" if email == admin_email else "tech"
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO users (username, display_name, password_hash, role, is_active, created_at, auth_provider, email)
            VALUES (?, ?, ?, ?, 1, ?, 'google', ?)
            """,
            (username, display_name or email, hash_password(os.urandom(32).hex()), role, current_timestamp(), email),
        )
        conn.commit()
    return get_user_by_email(email)


def update_user(user_id: int, display_name: str, role: str, is_active: bool) -> None:
    initialize_database()
    if role not in ("admin", "tech"):
        role = "tech"
    with get_connection() as conn:
        conn.execute(
            "UPDATE users SET display_name = ?, role = ?, is_active = ? WHERE id = ?",
            (display_name.strip(), role, 1 if is_active else 0, user_id),
        )
        conn.commit()


def delete_user(user_id: int) -> None:
    initialize_database()
    with get_connection() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()


def reset_user_password(user_id: int, new_password: str) -> None:
    initialize_database()
    with get_connection() as conn:
        conn.execute("UPDATE users SET password_hash = ?, auth_provider = 'local' WHERE id = ?", (hash_password(new_password), user_id))
        conn.commit()


def change_user_password(user_id: int, new_password: str) -> None:
    reset_user_password(user_id, new_password)


def list_cases(search: str = "", status: str = "All", part: str = "All", hide_complete: bool = False, followups_only: bool = False) -> list[dict]:
    initialize_database()
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM cases ORDER BY COALESCE(timestamp, '') DESC, id DESC").fetchall()
    cases = [row_to_case(row) for row in rows]
    if hide_complete:
        cases = [case for case in cases if case["status"] != "Complete"]
    if followups_only:
        cases = [case for case in cases if case["followup"]]
    if status and status != "All":
        cases = [case for case in cases if case["status"] == status]
    if part and part != "All":
        if part == "Other":
            cases = [case for case in cases if "Other:" in case["parts"]]
        else:
            cases = [case for case in cases if part.lower() in case["parts"].lower()]
    if search:
        q = search.lower()
        cases = [case for case in cases if q in " ".join(str(value).lower() for value in case.values())]
    return cases


def oldest_open_cases(limit: int = 25) -> list[dict]:
    open_cases = [case for case in list_cases() if case["status"] != "Complete"]
    open_cases.sort(key=lambda case: parse_timestamp(case.get("timestamp", "")))
    return open_cases[:limit]


def get_case(case_id: int) -> Optional[dict]:
    initialize_database()
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
    return row_to_case(row) if row else None


def validate_case_fields(work_order: str, serial_number: str, status: str) -> list[str]:
    errors = []
    if not work_order.strip():
        errors.append("Work Order is required.")
    if not serial_number.strip():
        errors.append("Serial Number is required.")
    if not status.strip():
        errors.append("Status is required.")
    if status and status not in STATUS_OPTIONS:
        errors.append("Status is not valid.")
    if len(work_order.strip()) > 10:
        errors.append("Work Order should be 10 characters or less.")
    if len(serial_number.strip()) > 12:
        errors.append("Serial Number looks too long.")
    return errors


def create_case(work_order: str, serial_number: str, status: str, parts: list[str], other: str, notes: str, changed_by: str = "") -> int:
    initialize_database()
    timestamp = current_timestamp()
    structured_notes = build_notes_field(parts, other, notes)
    with get_connection() as conn:
        if conn.is_postgres:
            cursor = conn.execute(
                """
                INSERT INTO cases (work_order, serial_number, status, notes, timestamp, followup, assigned_to)
                VALUES (?, ?, ?, ?, ?, 0, ?)
                RETURNING id
                """,
                (work_order.strip(), serial_number.strip().upper(), status.strip(), structured_notes, timestamp, changed_by),
            )
            case_id = int(cursor.fetchone()["id"])
        else:
            cursor = conn.execute(
                """
                INSERT INTO cases (work_order, serial_number, status, notes, timestamp, followup, assigned_to)
                VALUES (?, ?, ?, ?, ?, 0, ?)
                """,
                (work_order.strip(), serial_number.strip().upper(), status.strip(), structured_notes, timestamp, changed_by),
            )
            case_id = int(cursor.lastrowid)
        conn.execute(
            """
            INSERT INTO status_history (case_id, old_status, new_status, changed_by, changed_at, note)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (case_id, None, status.strip(), changed_by, timestamp, "Case created"),
        )
        conn.commit()
        return case_id


def update_case(case_id: int, work_order: str, serial_number: str, status: str, parts: list[str], other: str, notes: str, changed_by: str = "") -> None:
    initialize_database()
    timestamp = current_timestamp()
    structured_notes = build_notes_field(parts, other, notes)
    old_case = get_case(case_id)
    old_status = old_case["status"] if old_case else None
    with get_connection() as conn:
        conn.execute(
            "UPDATE cases SET work_order = ?, serial_number = ?, status = ?, notes = ?, timestamp = ? WHERE id = ?",
            (work_order.strip(), serial_number.strip().upper(), status.strip(), structured_notes, timestamp, case_id),
        )
        if old_status != status:
            conn.execute(
                """
                INSERT INTO status_history (case_id, old_status, new_status, changed_by, changed_at, note)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (case_id, old_status, status.strip(), changed_by, timestamp, "Status changed during case edit"),
            )
        conn.commit()


def delete_case(case_id: int) -> None:
    initialize_database()
    with get_connection() as conn:
        conn.execute("DELETE FROM status_history WHERE case_id = ?", (case_id,))
        conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
        conn.commit()


def update_status(case_id: int, status: str, changed_by: str = "") -> None:
    initialize_database()
    old_case = get_case(case_id)
    old_status = old_case["status"] if old_case else None
    timestamp = current_timestamp()
    with get_connection() as conn:
        conn.execute("UPDATE cases SET status = ?, timestamp = ? WHERE id = ?", (status, timestamp, case_id))
        if old_status != status:
            conn.execute(
                """
                INSERT INTO status_history (case_id, old_status, new_status, changed_by, changed_at, note)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (case_id, old_status, status, changed_by, timestamp, "Status updated"),
            )
        conn.commit()


def set_followup(case_id: int, followup: bool) -> None:
    initialize_database()
    with get_connection() as conn:
        conn.execute("UPDATE cases SET followup = ? WHERE id = ?", (1 if followup else 0, case_id))
        conn.commit()


def get_status_history(case_id: int) -> list[dict]:
    initialize_database()
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM status_history WHERE case_id = ? ORDER BY changed_at DESC, id DESC", (case_id,)).fetchall()
    return [dict(row) for row in rows]


def dashboard_counts(cases: Optional[list[dict]] = None) -> dict:
    cases = cases if cases is not None else list_cases()
    counts = {"Total": len(cases)}
    for status in STATUS_OPTIONS:
        counts[status] = sum(1 for case in cases if case["status"] == status)
    counts["Follow-ups"] = sum(1 for case in cases if case["followup"])
    counts["Repeat Serials"] = len(repeat_serial_groups())
    return counts


def analytics(cases: Optional[list[dict]] = None) -> dict:
    cases = cases if cases is not None else list_cases()
    total = len(cases) or 1
    open_count = sum(1 for case in cases if case["status"] != "Complete")
    complete_count = sum(1 for case in cases if case["status"] == "Complete")
    repeat_count = len(repeat_serial_groups())
    followup_count = sum(1 for case in cases if case["followup"])
    part_counts: dict[str, int] = {}
    for case in cases:
        parts = case.get("parts") or ""
        for part in [p.strip() for p in parts.split(",") if p.strip()]:
            part_counts[part] = part_counts.get(part, 0) + 1
    top_part = max(part_counts.items(), key=lambda item: item[1])[0] if part_counts else "None"
    return {"Open": open_count, "Complete %": f"{round((complete_count / total) * 100)}%", "Follow-ups": followup_count, "Repeat Serials": repeat_count, "Top Part": top_part}


def part_breakdown() -> list[dict]:
    counts: dict[str, int] = {}
    for case in list_cases():
        parts = case.get("parts") or ""
        for part in [p.strip() for p in parts.split(",") if p.strip()]:
            counts[part] = counts.get(part, 0) + 1
    return [{"part": part, "count": count} for part, count in sorted(counts.items(), key=lambda item: item[1], reverse=True)]


def aging_buckets() -> dict:
    buckets = {"0-3 days": 0, "4-7 days": 0, "8-14 days": 0, "15+ days": 0}
    now = datetime.now()
    for case in list_cases():
        if case["status"] == "Complete":
            continue
        changed = parse_timestamp(case.get("timestamp", ""))
        if changed == datetime.max:
            continue
        days = (now - changed).days
        if days <= 3:
            buckets["0-3 days"] += 1
        elif days <= 7:
            buckets["4-7 days"] += 1
        elif days <= 14:
            buckets["8-14 days"] += 1
        else:
            buckets["15+ days"] += 1
    return buckets


def repeat_serial_groups() -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for case in list_cases():
        serial = case["serial_number"].strip().upper()
        if serial:
            groups.setdefault(serial, []).append(case)
    return {serial: rows for serial, rows in groups.items() if len(rows) >= 2}


def normalize_csv_row(row: list[str], headers: Optional[list[str]] = None) -> Optional[dict]:
    row = [str(cell).strip() for cell in row]
    if not row or not any(row):
        return None
    if headers:
        values = {headers[i].strip().lower(): row[i] for i in range(min(len(headers), len(row)))}
        def first(*names: str) -> str:
            for name in names:
                value = values.get(name.lower(), "")
                if value:
                    return value
            return ""
        work_order = first("work order", "work_order", "wo", "ticket", "case")
        serial = first("serial number", "serial_number", "serial", "sn").upper()
        status = first("status") or "Ordered"
        parts_value = first("parts", "part")
        notes_value = first("notes", "note")
        timestamp = first("timestamp", "updated_at", "created_at", "date") or current_timestamp()
    else:
        if len(row) < 2:
            return None
        work_order = row[0]
        serial = row[1].upper()
        status = row[2] if len(row) > 2 and row[2] else "Ordered"
        parts_value = row[3] if len(row) >= 6 else ""
        notes_value = row[4] if len(row) >= 6 else (row[3] if len(row) > 3 else "")
        timestamp = row[5] if len(row) >= 6 and row[5] else (row[4] if len(row) > 4 and row[4] else current_timestamp())
    if not work_order and not serial:
        return None
    parts = []
    other = ""
    for item in [p.strip() for p in parts_value.split(",") if p.strip()]:
        if item in PART_OPTIONS:
            parts.append(item)
        elif item.lower().startswith("other:"):
            other = item.split(":", 1)[1].strip()
        else:
            other = item if not other else f"{other}, {item}"
    structured_notes = notes_value if notes_value.startswith("Parts:") else build_notes_field(parts, other, notes_value)
    return {"work_order": work_order, "serial_number": serial, "status": status, "notes": structured_notes, "timestamp": timestamp}


def import_csv_file(path: Path) -> tuple[int, int]:
    initialize_database()
    with open(path, "r", newline="", encoding="utf-8-sig") as file:
        rows = list(csv.reader(file))
    if not rows:
        return 0, 0
    headers = None
    start_index = 0
    first_row = ",".join(cell.strip().lower() for cell in rows[0])
    if any(marker in first_row for marker in ["work order", "serial", "status", "notes", "timestamp"]):
        headers = [cell.strip() for cell in rows[0]]
        start_index = 1
    imported = 0
    skipped = 0
    with get_connection() as conn:
        conn.execute("DELETE FROM status_history")
        conn.execute("DELETE FROM cases")
        if not conn.is_postgres:
            try:
                conn.execute("DELETE FROM sqlite_sequence WHERE name='cases'")
            except sqlite3.Error:
                pass
        for row in rows[start_index:]:
            normalized = normalize_csv_row(row, headers)
            if not normalized:
                skipped += 1
                continue
            if conn.is_postgres:
                cursor = conn.execute(
                    "INSERT INTO cases (work_order, serial_number, status, notes, timestamp, followup, assigned_to) VALUES (?, ?, ?, ?, ?, 0, '') RETURNING id",
                    (normalized["work_order"], normalized["serial_number"], normalized["status"], normalized["notes"], normalized["timestamp"]),
                )
                case_id = cursor.fetchone()["id"]
            else:
                cursor = conn.execute(
                    "INSERT INTO cases (work_order, serial_number, status, notes, timestamp, followup, assigned_to) VALUES (?, ?, ?, ?, ?, 0, '')",
                    (normalized["work_order"], normalized["serial_number"], normalized["status"], normalized["notes"], normalized["timestamp"]),
                )
                case_id = cursor.lastrowid
            conn.execute(
                "INSERT INTO status_history (case_id, old_status, new_status, changed_by, changed_at, note) VALUES (?, ?, ?, ?, ?, ?)",
                (case_id, None, normalized["status"], "import", normalized["timestamp"], "Imported from CSV"),
            )
            imported += 1
        conn.commit()
    return imported, skipped


def export_csv_file(path: Path) -> None:
    cases = list_cases()
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["Work Order", "Serial Number", "Status", "Parts", "Notes", "Timestamp", "Follow-up", "Assigned To"])
        for case in cases:
            writer.writerow([case["work_order"], case["serial_number"], case["status"], case["parts"], case["user_notes"], case["timestamp"], "Yes" if case["followup"] else "No", case["assigned_to"]])


def create_backup() -> Path:
    initialize_database()
    if using_postgres():
        dest = backup_dir() / f"lenovo_tracker_backup_{timestamp_for_filename()}.csv"
        export_csv_file(dest)
        return dest
    dest = backup_dir() / f"lenovo_tracker_backup_{timestamp_for_filename()}.db"
    shutil.copy2(db_path(), dest)
    return dest


def list_backups() -> list[dict]:
    rows = []
    for path in sorted(list(backup_dir().glob("*.db")) + list(backup_dir().glob("*.csv")), reverse=True):
        rows.append({"name": path.name, "size": path.stat().st_size, "modified": datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")})
    return rows


def backup_path(filename: str) -> Optional[Path]:
    safe = Path(filename).name
    path = backup_dir() / safe
    return path if path.exists() and path.suffix in (".db", ".csv") else None
