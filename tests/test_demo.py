"""The fictional sample room indexes and is searchable.

Run:  PYTHONPATH=. python3 tests/test_demo.py

Isolated via LAWDATAMAN_DATA_DIR, same rule as the other suites. Does not need
the Rust redaction binary.
"""

import os
import tempfile
from pathlib import Path

os.environ.setdefault("LAWDATAMAN_DATA_DIR", tempfile.mkdtemp(prefix="ldm-demo-"))
os.environ.setdefault("LAWDATAMAN_DISABLE_OS_OPEN", "1")

from fastapi.testclient import TestClient  # noqa: E402

from app.demo import prepare_demo, sample_room  # noqa: E402
from app.web import AppState, create_app  # noqa: E402


def test_sample_room_search_and_schedule():
    root = sample_room()
    assert root.is_dir(), root
    assert (root / "01-correspondence" / "engagement-letter.txt").is_file()

    db, name = prepare_demo()
    assert name == "sample-room", name
    assert Path(db).is_file()

    state = AppState()
    state.active_db = db
    state.active_name = name
    client = TestClient(create_app(state))
    client.headers.update({"X-DRR-Token": state.token})

    page = client.get("/app")
    assert page.status_code == 200
    state_body = client.get("/api/state").json()
    assert state_body["has_matter"] is True
    assert state_body["stats"]["total"] >= 3

    hits = client.get("/api/search", params={"q": "Harbour Lane"}).json()
    blob = " ".join(
        f"{h.get('filename','')} {h.get('snip','')}" for h in hits["results"]
    )
    assert "engagement-letter.txt" in blob or "Harbour" in blob
    assert len(hits["results"]) >= 2

    manifest = client.get("/api/tools/manifest").json()
    names = {row["filename"] for row in manifest["rows"]}
    assert "engagement-letter.txt" in names
    assert "completion-email.eml" in names
    assert "directors.md" in names


if __name__ == "__main__":
    test_sample_room_search_and_schedule()
    print("demo OK")
