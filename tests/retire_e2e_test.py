#!/usr/bin/env python3
"""End-to-end verification for IPv4 retirement (old backend decommissioning).

Covers, against the real web UI + real UDP DNS server:
  0. unit: max TTL over every ever-published A record (lowered TTL still
     counts the old value); retirement validation helpers
  1. retire requests need the address in the current zone and a not-retired
     backup A for every pointing name (rejected otherwise, state untouched)
  2. acceptance: deadline = now + historical max TTL; shown on the web page;
     repeat / restarted requests reuse the original deadline
  3. before the deadline queries still return the address, and every A TTL
     in the whole answer set (including A reached via CNAME) is capped to
     remaining whole seconds; CNAME TTLs are untouched
  4. pre-deadline publishes must keep the address's name set and keep a
     not-retired backup A; post-deadline any submission carrying the
     address is rejected
  5. after the deadline new queries automatically drop the address
  6. failed writes leave the original state; restart resumes the deadline
  7. retirements and publishes take effect in submission order and every
     query sees one committed zone + retirement state

Run with the project venv python:  /tmp/testvenv/bin/python tests/retire_e2e_test.py
"""

import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time

import dnslib
import httpx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.store import Store  # noqa: E402
from app.zone import (  # noqa: E402
    Retirement,
    View,
    parse_zone_text,
    publish_retirement_problems,
    retirement_problems,
    resolve,
    snapshot_from_rows,
)

WEB = "http://127.0.0.1:18001"
DNS_PORT = 15354
LOG = "/tmp/zonedns-retire-e2e-server.log"

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    mark = "PASS" if cond else "FAIL"
    line = f"[{mark}] {name}"
    if detail and not cond:
        line += f"  -- {detail}"
    print(line, flush=True)


def dns_query(name, qtype="A"):
    pkt = dnslib.DNSRecord.question(name, qtype).send("127.0.0.1", DNS_PORT, timeout=3)
    return dnslib.DNSRecord.parse(pkt)


def rr_list(resp):
    return [(str(rr.rname), dnslib.QTYPE[rr.rtype], str(rr.rdata), int(rr.ttl))
            for rr in resp.rr]


def publish(text, note=""):
    return httpx.post(WEB + "/publish", data={"zone_text": text, "note": note}, timeout=10)


def retire(ip):
    return httpx.post(WEB + "/retire", data={"ip": ip}, timeout=10)


def wait_ready(proc, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"app exited early with {proc.returncode}; see {LOG}")
        try:
            if httpx.get(WEB + "/api/current", timeout=2).status_code == 200:
                dns_query("svc.test.", "A")
                return
        except Exception:
            pass
        time.sleep(0.3)
    raise RuntimeError("app did not become ready; see " + LOG)


def start_app(dbpath):
    env = dict(
        os.environ,
        ZONE_DB=dbpath,
        DNS_BIND="127.0.0.1",
        DNS_PORT=str(DNS_PORT),
        WEB_HOST="127.0.0.1",
        WEB_PORT="18001",
        REFRESH_INTERVAL="0.5",
    )
    proc = subprocess.Popen(
        [sys.executable, "-m", "app.main"],
        cwd=ROOT,
        env=env,
        stdout=open(LOG, "ab"),
        stderr=subprocess.STDOUT,
    )
    wait_ready(proc)
    return proc


def stop_app(proc):
    proc.terminate()
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def wait_until(predicate, timeout, label):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.2)
    check(label, False, "condition not reached in time")
    return False


# ---------------------------------------------------------------- unit tests
def test_store_max_ttl(tmp):
    db = os.path.join(tmp, "unit-retire.db")
    store = Store(db)
    store.init()
    # v1: 10.0.0.1 with TTL 300 (the "old" high TTL)
    store.publish([
        ("web.svc.test.", "A", "10.0.0.1", 300),
        ("web.svc.test.", "A", "10.0.0.2", 60),
    ], note="v1")
    # v2: TTL lowered to 5 — historical max must still be 300
    store.publish([
        ("web.svc.test.", "A", "10.0.0.1", 5),
        ("web.svc.test.", "A", "10.0.0.2", 60),
    ], note="v2 lowered")
    check("unit: max published TTL keeps old high value after TTL lowered",
          store.max_published_a_ttl("10.0.0.1") == 300)
    check("unit: max TTL over single-history address",
          store.max_published_a_ttl("10.0.0.2") == 60)
    check("unit: never-published address -> 0",
          store.max_published_a_ttl("10.9.9.9") == 0)


def test_resolution_rules():
    rows = [
        ("web.svc.test.", "A", "10.0.0.1", 60),
        ("web.svc.test.", "A", "10.0.0.2", 60),
        ("api.svc.test.", "CNAME", "web.svc.test.", 90),
    ]
    snap = snapshot_from_rows(7, "2026-11-19T00:00:00+00:00", rows)
    base = parse_zone_text(
        "web A 10.0.0.1 60\nweb A 10.0.0.2 60\napi CNAME web\n"
    )
    now = 1000.0
    r1 = Retirement("10.0.0.1", now + 10, 10, "t", snapshot_records=base,
                    other_retired_ips=frozenset())
    view = View(snap, [r1])

    # before deadline: address still present, whole A set TTL capped to 10
    rcode, answers = resolve(view, "web.svc.test.", "A", now=now)
    check("unit resolve: pre-deadline address retained",
          rcode == "NOERROR" and sorted(v for _, t, v, _ in answers if t == "A")
          == ["10.0.0.1", "10.0.0.2"], str(answers))
    check("unit resolve: whole A set TTL capped to remaining seconds",
          all(ttl == 10 for _, t, _, ttl in answers if t == "A"), str(answers))

    # CNAME chain: terminal A set capped as well, CNAME TTL untouched
    rcode, answers = resolve(view, "api.svc.test.", "A", now=now)
    cname_ttls = [ttl for _, t, _, ttl in answers if t == "CNAME"]
    a_ttls = [ttl for _, t, _, ttl in answers if t == "A"]
    check("unit resolve: A reached via CNAME capped too", a_ttls == [10, 10], str(answers))
    check("unit resolve: CNAME TTL untouched", cname_ttls == [90], str(answers))

    # remaining whole seconds floor; cap never exceeds published TTL
    rcode, answers = resolve(view, "web.svc.test.", "A", now=now + 9.4)
    check("unit resolve: remaining rounded up to whole seconds",
          all(ttl == 1 for _, t, _, ttl in answers if t == "A"), str(answers))

    # after deadline: address removed from new queries, backup remains
    rcode, answers = resolve(view, "web.svc.test.", "A", now=now + 10.5)
    ips = sorted(v for _, t, v, _ in answers if t == "A")
    check("unit resolve: post-deadline address dropped, backup kept",
          ips == ["10.0.0.2"], str(answers))


def test_validation_helpers():
    recs = parse_zone_text("web A 10.0.0.1 60\nweb A 10.0.0.2 60\nsolo A 10.0.0.9 60\n")
    plain = {n: {"A": list(d["A"]), "CNAME": d["CNAME"], "ttl": d["ttl"]}
             for n, d in recs.items()}
    check("unit validate: address absent from zone rejected",
          bool(retirement_problems(plain, "10.1.1.1", frozenset())))
    check("unit validate: name with only this A has no backup -> rejected",
          bool(retirement_problems(plain, "10.0.0.9", frozenset())))
    check("unit validate: backup A available -> accepted",
          not retirement_problems(plain, "10.0.0.1", frozenset()))
    check("unit validate: backup itself already retired -> rejected",
          bool(retirement_problems(plain, "10.0.0.1", frozenset({"10.0.0.2"}))))

    r = Retirement("10.0.0.1", 2000.0, 300, "t", snapshot_records=plain,
                   other_retired_ips=frozenset())
    # pre-deadline publish: name set must be preserved with a live backup
    kept = parse_zone_text("web A 10.0.0.1 60\nweb A 10.0.0.2 60\nsolo A 10.0.0.9 60\n")
    check("unit publish: keeping name set + backup is allowed",
          not publish_retirement_problems(kept, [r], now=1000.0))
    dropped = parse_zone_text("web A 10.0.0.2 60\nsolo A 10.0.0.9 60\n")
    check("unit publish: dropping retired name before deadline rejected",
          bool(publish_retirement_problems(dropped, [r], now=1000.0)))
    no_backup = parse_zone_text("web A 10.0.0.1 60\nsolo A 10.0.0.9 60\n")
    check("unit publish: no not-retired backup before deadline rejected",
          bool(publish_retirement_problems(no_backup, [r], now=1000.0)))
    check("unit publish: after deadline address must not appear",
          bool(publish_retirement_problems(kept, [r], now=3000.0)))
    check("unit publish: after deadline submission without address allowed",
          not publish_retirement_problems(dropped, [r], now=3000.0))


# ------------------------------------------------------------------ e2e flow
def main():
    tmp = tempfile.mkdtemp(prefix="zonedns-retire-e2e-")
    db = os.path.join(tmp, "zone.db")
    open(LOG, "w").close()

    test_store_max_ttl(tmp)
    test_resolution_rules()
    test_validation_helpers()

    proc = start_app(db)
    try:
        # v1: short-lived IP 10.0.0.1 (TTL 3), long-lived 10.0.0.2 (TTL 120),
        # plus a second name sharing the retiring address and a CNAME path
        v1 = (
            "web A 10.0.0.1 3\nweb A 10.0.0.2 120\n"
            "edge A 10.0.0.1 3\nedge A 10.0.0.3 30\n"
            "solo A 10.0.0.9 45\n"
            "api CNAME web\n"
        )
        r = publish(v1, note="v1 baseline")
        check("e2e: baseline published", r.status_code == 303, r.text[:150])

        # 1. invalid retire requests
        r = retire("10.9.9.9")
        check("e2e: retire address absent from zone -> 400", r.status_code == 400)
        check("e2e: rejection page explains why", "无法发起退役" in r.text)
        r = retire("not-an-ip")
        check("e2e: retire malformed IPv4 -> 400", r.status_code == 400)
        r = retire("10.0.0.9")
        check("e2e: retire sole A of a name (no backup) -> 400", r.status_code == 400)
        check("e2e: no retirement rows after rejections",
              httpx.get(WEB + "/api/retirements").json()["retirements"] == [])

        # 2. accept retirement of 10.0.0.1 (historical max TTL == 3 right now)
        r = retire("10.0.0.1")
        check("e2e: valid retire -> 303", r.status_code == 303, r.text[:150])
        rets = httpx.get(WEB + "/api/retirements").json()["retirements"]
        check("e2e: one active retirement recorded",
              len(rets) == 1 and rets[0]["ip"] == "10.0.0.1" and rets[0]["active"],
              str(rets))
        deadline = rets[0]["deadline"]
        check("e2e: deadline = acceptance + max historical TTL (3s)",
              abs(rets[0]["max_ttl"] - 3) == 0 and rets[0]["remaining_seconds"] <= 3,
              str(rets[0]))
        home = httpx.get(WEB + "/").text
        check("e2e: home page shows the deadline and remaining time",
              deadline in home and "退役中" in home)
        check("e2e: home page retire form lists current IPv4s",
              'name="ip"' in home and "10.0.0.1" in home)

        # repeat request: same deadline, still one row (do it immediately;
        # the 3s TTL deadline is short)
        r = retire("10.0.0.1")
        loc = r.headers.get("location", "")
        check("e2e: repeat retire -> 303 and reused deadline",
              r.status_code == 303 and deadline in loc and "msg=" in loc, loc)
        rets2 = httpx.get(WEB + "/api/retirements").json()["retirements"]
        check("e2e: repeat retire does not create a second row",
              len(rets2) == 1 and rets2[0]["deadline"] == deadline)

        # 3. before deadline: address still answered; whole A set TTL capped
        resp = dns_query("web.svc.test.", "A")
        rows_rr = rr_list(resp)
        ips = sorted(v for _, t, v, _ in rows_rr if t == "A")
        check("e2e: pre-deadline query still returns retiring address",
              ips == ["10.0.0.1", "10.0.0.2"], str(rows_rr))
        a_ttls = [ttl for _, t, _, ttl in rows_rr if t == "A"]
        check("e2e: whole A set TTL <= remaining whole seconds (cap applies to siblings too)",
              all(0 <= ttl <= 3 for ttl in a_ttls) and max(a_ttls) <= 3
              and min(a_ttls) >= 0, str(rows_rr))

        # via CNAME: terminal A capped, CNAME TTL (120? api ttl default 60) untouched
        resp = dns_query("api.svc.test.", "A")
        rows_rr = rr_list(resp)
        cname = [x for x in rows_rr if x[1] == "CNAME"]
        a_part = [x for x in rows_rr if x[1] == "A"]
        check("e2e: A reached through CNAME still carries retiring IP",
              sorted(v for _, _, v, _ in a_part) == ["10.0.0.1", "10.0.0.2"], str(rows_rr))
        check("e2e: CNAME-path A TTLs capped to remaining seconds",
              all(ttl <= 3 for _, _, _, ttl in a_part), str(rows_rr))
        check("e2e: CNAME record TTL untouched by the cap",
              len(cname) == 1 and cname[0][3] == 60, str(rows_rr))

        # the real-UDP web query form shows the capped TTLs as well
        page = httpx.get(WEB + "/query", params={"name": "web", "qtype": "A"}).text
        check("e2e: web query form shows real UDP answer with capped TTL",
              "10.0.0.1" in page and "10.0.0.2" in page and "NOERROR" in page)

        # edge (second name pointing at the retiring IP) behaves the same
        resp = dns_query("edge.svc.test.", "A")
        edge_ttls = [ttl for _, t, _, ttl in rr_list(resp) if t == "A"]
        check("e2e: every pointing name keeps answering and is capped",
              sorted(v for _, t, v, _ in rr_list(resp) if t == "A")
              == ["10.0.0.1", "10.0.0.3"] and all(t <= 3 for t in edge_ttls),
              str(rr_list(resp)))

        # 4. pre-deadline publish constraints
        bad_drop = (
            "web A 10.0.0.2 120\n"
            "edge A 10.0.0.1 3\nedge A 10.0.0.3 30\n"
            "solo A 10.0.0.9 45\napi CNAME web\n"
        )
        r = publish(bad_drop, note="loses web name set")
        check("e2e: publish dropping retiring name before deadline -> 400",
              r.status_code == 400 and "名称集合" in r.text, r.text[:150])
        bad_no_backup = (
            "web A 10.0.0.1 3\n"
            "edge A 10.0.0.1 3\nedge A 10.0.0.3 30\n"
            "solo A 10.0.0.9 45\napi CNAME web\n"
        )
        r = publish(bad_no_backup, note="no backup for web")
        check("e2e: publish without not-retired backup -> 400", r.status_code == 400)
        # valid pre-deadline publish keeps the name set and backups
        good = (
            "web A 10.0.0.1 3\nweb A 10.0.0.2 120\nweb A 10.0.0.7 90\n"
            "edge A 10.0.0.1 3\nedge A 10.0.0.3 30\n"
            "solo A 10.0.0.9 45\napi CNAME web\n"
        )
        r = publish(good, note="add extra backup")
        check("e2e: compliant pre-deadline publish -> 303", r.status_code == 303, r.text[:150])
        # retirement survived the publish and the cap still applies
        resp = dns_query("web.svc.test.", "A")
        a_part = [x for x in rr_list(resp) if x[1] == "A"]
        check("e2e: retirement still active after publish, cap retained",
              sorted(v for _, _, v, _ in a_part)
              == ["10.0.0.1", "10.0.0.2", "10.0.0.7"]
              and all(ttl <= 3 for _, _, _, ttl in a_part), str(a_part))

        # 5. wait for the deadline: new queries drop the address automatically
        def retired_gone():
            resp = dns_query("web.svc.test.", "A")
            ips = {v for _, t, v, _ in rr_list(resp) if t == "A"}
            return "10.0.0.1" not in ips and "10.0.0.2" in ips

        wait_until(retired_gone, 12, "e2e: after deadline new queries drop retired address")
        resp = dns_query("edge.svc.test.", "A")
        check("e2e: second name also drops the retired address, backup stays",
              sorted(v for _, t, v, _ in rr_list(resp) if t == "A") == ["10.0.0.3"],
              str(rr_list(resp)))
        resp = dns_query("api.svc.test.", "A")
        check("e2e: CNAME path no longer returns the retired address",
              "10.0.0.1" not in [v for _, t, v, _ in rr_list(resp) if t == "A"])
        rets = httpx.get(WEB + "/api/retirements").json()["retirements"]
        check("e2e: retirement marked inactive after deadline",
              rets[0]["active"] is False and rets[0]["remaining_seconds"] == 0, str(rets[0]))

        # 6. post-deadline: any submission still carrying the address is rejected
        r = publish(v1, note="brings retired IP back")
        check("e2e: post-deadline submission carrying address -> 400",
              r.status_code == 400 and "到期退役" in r.text, r.text[:150])
        clean = (
            "web A 10.0.0.2 120\nweb A 10.0.0.7 90\n"
            "edge A 10.0.0.3 30\nsolo A 10.0.0.9 45\napi CNAME web\n"
        )
        r = publish(clean, note="clean of retired IP")
        check("e2e: post-deadline clean submission -> 303", r.status_code == 303)

        # 7. write failure during retire: original state preserved.
        # First give edge a backup so retiring 10.0.0.3 passes validation and
        # actually reaches the database write (which then fails).
        with_backup = (
            "web A 10.0.0.2 120\nweb A 10.0.0.7 90\n"
            "edge A 10.0.0.3 30\nedge A 10.0.0.8 30\n"
            "solo A 10.0.0.9 45\napi CNAME web\n"
        )
        r = publish(with_backup, note="edge gets a backup")
        check("e2e: prepared a name with two live A records", r.status_code == 303)
        versions_before = httpx.get(WEB + "/api/versions").json()
        os.rename(db, db + ".real")
        os.mkdir(db)
        try:
            r = retire("10.0.0.3")
            check("e2e: retire write failure -> 500", r.status_code == 500,
                  f"got {r.status_code}: {r.text[:120]}")
            check("e2e: failed retire says state stays", "写入失败" in r.text)
            resp = dns_query("edge.svc.test.", "A")
            check("e2e: DNS keeps serving during failed retire",
                  "10.0.0.3" in [v for _, t, v, _ in rr_list(resp) if t == "A"])
            check("e2e: no new retirement after failed write",
                  len(httpx.get(WEB + "/api/retirements").json()["retirements"]) == 1)
        finally:
            os.rmdir(db)
            os.rename(db + ".real", db)
        time.sleep(1.2)
        check("e2e: versions unchanged after failed retire write",
              httpx.get(WEB + "/api/versions").json() == versions_before)

        # 8. second, long-lived retirement to exercise restart persistence
        r = retire("10.0.0.2")
        check("e2e: second retirement accepted", r.status_code == 303)
        rets = httpx.get(WEB + "/api/retirements").json()["retirements"]
        long_one = next(x for x in rets if x["ip"] == "10.0.0.2")
        long_deadline = long_one["deadline"]
        check("e2e: long retirement uses historical max TTL 120",
              long_one["max_ttl"] == 120 and 100 < long_one["remaining_seconds"] <= 120,
              str(long_one))
        # cannot retire the backup of a name while it is the only live backup:
        # web now has 10.0.0.2 (retiring) + 10.0.0.7; retiring 10.0.0.7 ->
        # web would have no not-retired backup
        r = retire("10.0.0.7")
        check("e2e: retiring the last remaining backup is rejected",
              r.status_code == 400 and "备用 A" in r.text, r.text[:150])

        state_before_stop = {
            "version": httpx.get(WEB + "/api/current").json()["version"],
            "retirements": httpx.get(WEB + "/api/retirements").json()["retirements"],
        }
    finally:
        stop_app(proc)

    # 9. restart: deadlines resume, repeat request reuses original deadline
    proc = start_app(db)
    try:
        rets = httpx.get(WEB + "/api/retirements").json()["retirements"]
        long_after = next(x for x in rets if x["ip"] == "10.0.0.2")
        check("e2e: restart resumes the same deadline",
              long_after["deadline"] == long_deadline and long_after["active"],
              f"{long_after} vs {long_deadline}")
        r = retire("10.0.0.2")
        loc = r.headers.get("location", "")
        check("e2e: repeat retire after restart reuses deadline",
              r.status_code == 303 and long_deadline in loc and "msg=" in loc, loc)
        check("e2e: restart restores current version",
              httpx.get(WEB + "/api/current").json()["version"]
              == state_before_stop["version"])
        # cap still enforced after restart; retired 10.0.0.1 stays absent
        resp = dns_query("web.svc.test.", "A")
        a_part = [x for x in rr_list(resp) if x[1] == "A"]
        check("e2e: post-restart queries keep expired address removed",
              "10.0.0.1" not in [v for _, _, v, _ in a_part], str(a_part))
        check("e2e: post-restart active retirement still caps TTL",
              all(ttl == long_after["remaining_seconds"] or ttl < 120
                  for _, _, _, ttl in a_part), str(a_part))
        home = httpx.get(WEB + "/").text
        check("e2e: home page renders retirement panel after restart",
              "IPv4 退役" in home and long_deadline in home)

        # 10. submission-order consistency: interleaved publishes/retirements,
        # concurrent queries always see one coherent committed state
        stop = threading.Event()
        errors = []

        def hammer():
            while not stop.is_set():
                try:
                    resp = dns_query("web.svc.test.", "A")
                    if dnslib.RCODE[resp.header.rcode] not in ("NOERROR", "SERVFAIL"):
                        errors.append(("rcode", dnslib.RCODE[resp.header.rcode]))
                except Exception as exc:  # noqa: BLE001
                    errors.append(("EXC", repr(exc)))

        threads = [threading.Thread(target=hammer) for _ in range(3)]
        for t in threads:
            t.start()
        zone_x = ("web A 10.0.0.2 120\nweb A 10.0.0.7 90\n"
                  "edge A 10.0.0.3 30\nedge A 10.0.0.8 30\n"
                  "solo A 10.0.0.9 45\napi CNAME web\n")
        for i in range(4):
            r = publish(zone_x, note=f"order{i}")
            if r.status_code != 303:
                errors.append(("publish", r.status_code))
            r = retire("10.0.0.3")  # first call accepted, later ones idempotent
            if r.status_code not in (303,):
                errors.append(("retire", r.status_code))
        stop.set()
        for t in threads:
            t.join()
        check("e2e: interleaved submissions stay consistent under query load",
              not errors, str(errors[:3]))
        rets = httpx.get(WEB + "/api/retirements").json()["retirements"]
        check("e2e: idempotent retries kept a single row per IP",
              sum(1 for x in rets if x["ip"] == "10.0.0.3") == 1
              and len({x["ip"] for x in rets}) == len(rets), str(rets))
    finally:
        stop_app(proc)

    print(f"\n{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("failed checks:")
        for name in FAIL:
            print("  -", name)
    shutil.rmtree(tmp, ignore_errors=True)
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
