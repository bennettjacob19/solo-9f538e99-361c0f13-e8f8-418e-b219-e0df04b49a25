"""Entrypoint: wire up storage, committed view, DNS server, and web UI.

Run:  python -m app.main
Env:  ZONE_DB (default ./data/zone.db), DNS_BIND (0.0.0.0), DNS_PORT (5353),
      WEB_HOST (0.0.0.0), WEB_PORT (8000), REFRESH_INTERVAL (2.0 seconds)
"""

import os
import sys
import threading
import time

import uvicorn

from .deps import runtime
from .dns_server import start_dns_server
from .store import Store
from .zone import Retirement, View, snapshot_from_rows


def log(msg):
    print(f"[zonedns] {msg}", file=sys.stderr, flush=True)


def build_view():
    """Rebuild the committed View from SQLite: current zone snapshot plus
    every persisted retirement (deadlines are absolute and simply resume
    ticking after a restart)."""
    current = runtime.store.load_current()
    snapshot = None
    if current is not None:
        snapshot = snapshot_from_rows(
            current["id"], current["created_at"], current["rows"]
        )
    retirements = []
    rows = runtime.store.list_retirements()
    all_ips = frozenset(r["ip"] for r in rows)
    for row in rows:
        snap_records = snapshot.records if snapshot is not None else None
        retirements.append(
            Retirement(
                row["ip"], row["deadline"], row["max_ttl"], row["created_at"],
                snapshot_records=snap_records,
                other_retired_ips=all_ips - {row["ip"]},
            )
        )
    return View(snapshot, retirements)


def load_current_into_holder():
    view = build_view()
    if view.snapshot is None:
        log("no published version in database yet")
    else:
        log(f"loaded current version v{view.snapshot.version_id} "
            f"({len(view.snapshot.records)} names) from database")
    if view.retirements:
        log(f"loaded {len(view.retirements)} retirement(s) from database")
    runtime.holder.set(view)


def refresh_loop():
    """Safety net: re-sync the in-memory view with the DB state.

    Normal publishes/retirements swap the view immediately; this only
    matters if the DB changed out-of-band. Reads never block queries."""
    while True:
        time.sleep(runtime.refresh_interval)
        try:
            view = runtime.holder.get()
            db_vid = runtime.store.current_version_id()
            db_rets = runtime.store.list_retirements()
            mem_vid = view.snapshot.version_id if view and view.snapshot else None
            mem_rets = [
                (r.ip, r.deadline) for r in view.retirements
            ] if view else []
            if mem_vid != db_vid or mem_rets != [(r["ip"], r["deadline"]) for r in db_rets]:
                log("refresh: DB state differs from memory, reloading view")
                load_current_into_holder()
        except Exception as exc:  # keep serving the in-memory view
            log(f"refresh: {exc!r}")


def main():
    db_path = os.environ.get("ZONE_DB", os.path.join("data", "zone.db"))
    dns_bind = os.environ.get("DNS_BIND", "0.0.0.0")
    dns_port = int(os.environ.get("DNS_PORT", "5353"))
    web_host = os.environ.get("WEB_HOST", "0.0.0.0")
    web_port = int(os.environ.get("WEB_PORT", "8000"))
    runtime.refresh_interval = float(os.environ.get("REFRESH_INTERVAL", "2.0"))

    db_dir = os.path.dirname(os.path.abspath(db_path))
    os.makedirs(db_dir, exist_ok=True)

    runtime.store = Store(db_path)
    runtime.store.init()
    runtime.dns_query_host = os.environ.get("DNS_QUERY_HOST", "127.0.0.1")
    runtime.dns_query_port = dns_port

    load_current_into_holder()  # restart: resume exactly the committed state

    start_dns_server(runtime.holder.get, dns_bind, dns_port)
    log(f"authoritative UDP DNS for svc.test. on {dns_bind}:{dns_port}")

    threading.Thread(target=refresh_loop, daemon=True).start()

    log(f"web UI on http://{web_host}:{web_port}")
    uvicorn.run("app.web:app", host=web_host, port=web_port, log_level="info")


if __name__ == "__main__":
    main()
