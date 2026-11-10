"""Scrub the synthetic demo case so screenshots show demo identity only."""

import json
import pathlib
import sqlite3

CASE = pathlib.Path("cases") / "20261110-152322-demo-src"
REPO = pathlib.Path(__file__).resolve().parent.parent
CASE = REPO / CASE


def main() -> None:
    db = sqlite3.connect(CASE / "ledger.sqlite")
    db.execute("UPDATE rows SET user_name='demo', host='DEMO-PC'")
    old = str(REPO).replace("\\", "/")
    rows = db.execute("SELECT id, source_file FROM rows WHERE source_file IS NOT NULL").fetchall()
    for row_id, src in rows:
        db.execute(
            "UPDATE rows SET source_file=? WHERE id=?",
            (src.replace(old, "C:/demo").replace(str(REPO), "C:/demo"), row_id),
        )
    db.execute("UPDATE meta SET v='demo' WHERE k='user'")
    db.execute("UPDATE meta SET v='DEMO-PC' WHERE k='host'")
    db.commit()
    print("meta:", dict(db.execute("SELECT k, v FROM meta WHERE k IN ('user','host')")))
    db.close()

    case_json = CASE / "case.json"
    data = json.loads(case_json.read_text())
    data["user"] = "demo"
    data["host"] = "DEMO-PC"
    old = str(REPO).replace("/", "\\")
    data["roots"] = [r.replace(old, "C:\\demo") for r in data["roots"]]
    case_json.write_text(json.dumps(data, indent=2))
    print("case.json updated")


if __name__ == "__main__":
    main()
