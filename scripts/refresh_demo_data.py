"""
Refresh OpenCase with polished fictional demo data.

Run this only against your portfolio/demo database. It deletes existing cases and
status history, then inserts realistic-looking fictional repair records.

PowerShell from repo root:
    python scripts/refresh_demo_data.py
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from pathlib import Path
import sys

# Allow running from repo root without installing the package.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app import database as db  # noqa: E402

random.seed(42)

STATUSES = [
    ("Complete", 72),
    ("Replaced", 18),
    ("Returned", 10),
    ("Pending", 11),
    ("Ordered", 9),
]

PART_SETS = [
    ["LCD"],
    ["Keyboard"],
    ["Top lid", "LCD"],
    ["Hinges"],
    ["Bezel", "LCD"],
    ["Motherboard"],
    ["Top lid", "Hinges"],
]

NOTE_TEMPLATES = [
    "Screen has pressure damage near the lower bezel. Replacement panel ordered after visual inspection.",
    "Keyboard has several non-responsive keys. Device is usable with external keyboard while parts are pending.",
    "Hinge assembly is loose and separating from the top cover. Holding for part availability before repair.",
    "Display flickers intermittently after lid movement. Cable seating checked; panel replacement recommended.",
    "Top cover has cracked mounting points around the hinge. Repair requires top lid and hinge set.",
    "Unit powers on but does not complete display output reliably. Board-level issue suspected after basic testing.",
    "Bezel clips are damaged and the panel is shifting in the frame. Replacing bezel with display service.",
    "Returned from vendor repair. Verified boot, wireless connectivity, keyboard input, and camera operation.",
    "Part installed and device passed checkout. Ready to return to the assigned location.",
    "Waiting on vendor update. Follow-up needed if the part does not move by the next review cycle.",
    "Repeat repair on the same serial. Flagged for review before another part order is submitted.",
    "Cosmetic damage noted, but failure affects daily use. Repair approved after support review.",
]

LOCATIONS = ["North Campus", "South Campus", "Media Center", "Front Office", "Lab Cart", "Spare Pool", "Grade 6 Cart", "Grade 8 Cart"]

REPEAT_SERIALS = [
    "PF4X2Q91",
    "PW03KD8A",
    "PF9W3922",
    "LR81T2K4",
    "YD44M8QA",
    "MX72Q1LP",
    "CA91P4W2",
    "RK28T7DN",
]


def clear_cases() -> None:
    db.initialize_database()
    with db.get_connection() as conn:
        conn.execute("DELETE FROM status_history")
        conn.execute("DELETE FROM cases")
        if not conn.is_postgres:
            try:
                conn.execute("DELETE FROM sqlite_sequence WHERE name='cases'")
            except Exception:
                pass
        conn.commit()


def build_serial(index: int) -> str:
    # Every repeat serial appears exactly twice, producing eight repeat groups.
    if index < len(REPEAT_SERIALS) * 2:
        return REPEAT_SERIALS[index % len(REPEAT_SERIALS)]
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "OC" + "".join(random.choice(chars) for _ in range(8))


def flatten_statuses() -> list[str]:
    rows: list[str] = []
    for status, count in STATUSES:
        rows.extend([status] * count)
    random.shuffle(rows)
    return rows


def main() -> None:
    clear_cases()
    statuses = flatten_statuses()
    now = datetime.now().replace(microsecond=0)
    created_ids: list[int] = []

    for i, status in enumerate(statuses):
        work_order = str(480000 + i * 7 + random.randint(0, 5))
        serial = build_serial(i)
        parts = random.choice(PART_SETS)
        location = random.choice(LOCATIONS)
        note = random.choice(NOTE_TEMPLATES)
        if i % 9 == 0:
            note = f"{note} Location: {location}."
        age_days = random.randint(0, 45) if status != "Complete" else random.randint(0, 90)
        timestamp = (now - timedelta(days=age_days, hours=random.randint(0, 8), minutes=random.randint(0, 50))).strftime("%Y-%m-%d %H:%M:%S")
        structured_notes = db.build_notes_field(parts, "", note)

        with db.get_connection() as conn:
            if conn.is_postgres:
                cursor = conn.execute(
                    """
                    INSERT INTO cases (work_order, serial_number, status, notes, timestamp, followup, assigned_to)
                    VALUES (?, ?, ?, ?, ?, 0, ?) RETURNING id
                    """,
                    (work_order, serial, status, structured_notes, timestamp, "Demo Technician"),
                )
                case_id = int(cursor.fetchone()["id"])
            else:
                cursor = conn.execute(
                    """
                    INSERT INTO cases (work_order, serial_number, status, notes, timestamp, followup, assigned_to)
                    VALUES (?, ?, ?, ?, ?, 0, ?)
                    """,
                    (work_order, serial, status, structured_notes, timestamp, "Demo Technician"),
                )
                case_id = int(cursor.lastrowid)
            conn.execute(
                """
                INSERT INTO status_history (case_id, old_status, new_status, changed_by, changed_at, note)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (case_id, None, status, "demo seed", timestamp, "Seeded fictional portfolio record"),
            )
            conn.commit()
        created_ids.append(case_id)

    # Keep follow-up count intentional and easy to verify.
    for case_id in created_ids[:2]:
        db.set_followup(case_id, True)

    print(f"Inserted {len(created_ids)} fictional demo cases.")
    print("Expected repeat serial groups: 8")
    print("Expected follow-up flags: 2")


if __name__ == "__main__":
    main()
