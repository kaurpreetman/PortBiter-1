import sqlite3

from backend_v2.state import ScanState, DB_PATH


def test_state_persistence_roundtrip():
    scan_id = "test-scan"
    state = ScanState(target_url="http://example.com", scan_id=scan_id)
    state.logs.append("test log")
    state.vulnerabilities.append({"id": "v1", "type": "test"})
    state.save()

    connection = sqlite3.connect(DB_PATH)
    cursor = connection.cursor()
    cursor.execute("SELECT target_url, logs, vulnerabilities FROM scans WHERE scan_id = ?", (scan_id,))
    row = cursor.fetchone()
    connection.close()

    assert row is not None
    assert row[0] == "http://example.com"
    assert "test log" in row[1]
    assert "test" in row[2]
