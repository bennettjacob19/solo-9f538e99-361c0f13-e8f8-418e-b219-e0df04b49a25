"""Zone text parsing, whole-version validation, immutable snapshots, and
single-version resolution for the svc.test. authoritative zone."""

import ipaddress
import math
import re
import threading
import time
from datetime import datetime, timezone

ZONE = "svc.test."
DEFAULT_TTL = 60
MAX_TTL = 2_147_483_647

_LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")


class ZoneError(Exception):
    """Raised when a candidate zone version fails validation.

    Carries the full list of human-readable problems; the whole version
    is rejected, nothing is published.
    """

    def __init__(self, errors):
        self.errors = list(errors)
        super().__init__("; ".join(self.errors))


def fqdn(name):
    """Normalize an operator-supplied name to an in-zone FQDN.

    Accepts relative names ("web"), zone FQDNs ("web.svc.test."), and the
    zone apex. Rejects anything outside the zone.
    """
    n = (name or "").strip().lower().rstrip(".")
    if not n:
        raise ValueError("empty name")
    if n == ZONE[:-1]:
        return ZONE
    if n.endswith("." + ZONE[:-1]):
        candidate = n + "."
    elif "." in n:
        raise ValueError(f"name '{name}' is outside zone {ZONE}")
    else:
        candidate = n + "." + ZONE
    _check_name(candidate)
    return candidate


def _check_name(name):
    if len(name) > 253:
        raise ValueError(f"name too long: {name}")
    for label in name.rstrip(".").split("."):
        if not _LABEL_RE.match(label):
            raise ValueError(f"bad label '{label}' in {name}")


def parse_zone_text(text):
    """Parse and validate a full zone version.

    Line format:  <name> <A|CNAME> <value> [ttl]     (# starts a comment)

    Returns {name: {"A": [ip, ...], "CNAME": target|None, "ttl": int}}.
    Raises ZoneError listing every problem found; nothing is half-accepted.
    """
    records = {}
    errors = []

    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 3:
            errors.append(f"line {lineno}: expected '<name> <A|CNAME> <value> [ttl]'")
            continue
        if len(parts) > 4:
            errors.append(f"line {lineno}: too many fields")
            continue
        name_s, rtype, value = parts[0], parts[1].upper(), parts[2]
        ttl = DEFAULT_TTL
        if len(parts) == 4:
            try:
                ttl = int(parts[3])
                if not (0 < ttl <= MAX_TTL):
                    raise ValueError
            except ValueError:
                errors.append(f"line {lineno}: bad ttl '{parts[3]}'")
                continue
        try:
            name = fqdn(name_s)
        except ValueError as exc:
            errors.append(f"line {lineno}: {exc}")
            continue
        rec = records.setdefault(name, {"A": [], "CNAME": None, "ttl": ttl})

        if rtype == "A":
            try:
                ip = str(ipaddress.IPv4Address(value))
            except ValueError:
                errors.append(f"line {lineno}: invalid IPv4 address '{value}'")
                continue
            if ip not in rec["A"]:
                rec["A"].append(ip)
        elif rtype == "CNAME":
            try:
                target = fqdn(value)
            except ValueError:
                errors.append(
                    f"line {lineno}: CNAME target '{value}' is not a name inside {ZONE}"
                )
                continue
            if rec["CNAME"] is not None:
                errors.append(f"line {lineno}: duplicate CNAME for {name}")
                continue
            rec["CNAME"] = target
        else:
            errors.append(f"line {lineno}: unsupported record type '{parts[1]}' (A/CNAME only)")

    errors.extend(validate_records(records))
    if errors:
        raise ZoneError(errors)
    return records


def validate_records(records):
    """Cross-record rules for one candidate version.

    - a name cannot hold both A and CNAME
    - every CNAME target must exist in this same version (no dangling)
    - CNAME chains must be acyclic and terminate at a name with A record(s)
    """
    errors = []
    for name in sorted(records):
        rec = records[name]
        if rec["A"] and rec["CNAME"]:
            errors.append(f"{name}: cannot have both A and CNAME records")

    for name in sorted(records):
        rec = records[name]
        if not rec["CNAME"]:
            continue
        seen = {name}
        node = rec["CNAME"]
        while True:
            target = records.get(node)
            if target is None:
                errors.append(
                    f"{name}: CNAME target {node} is not defined in this version (dangling)"
                )
                break
            if node in seen:
                errors.append(f"{name}: CNAME chain loops back to {node} (cycle)")
                break
            seen.add(node)
            if target["CNAME"]:
                node = target["CNAME"]
                continue
            if target["A"]:
                break  # chain ends at address records: OK
            break  # pragma: no cover - a stored record always has A or CNAME
    return errors


def flatten_records(records):
    """parsed-dict -> list of (name, rtype, value, ttl) rows for storage."""
    rows = []
    for name in sorted(records):
        rec = records[name]
        for ip in rec["A"]:
            rows.append((name, "A", ip, rec["ttl"]))
        if rec["CNAME"]:
            rows.append((name, "CNAME", rec["CNAME"], rec["ttl"]))
    return rows


def names_holding_ip(records, ip):
    """All in-zone names whose A set contains this IPv4."""
    return sorted(name for name, rec in records.items() if ip in rec["A"])


def retirement_problems(records, ip, retired_ips):
    """Validate a request to retire `ip` against the current version.

    The address must currently be published, and every name pointing at it
    must keep at least one *not-yet-retired* backup A record. The candidate
    address itself counts as retired, so a name whose only A is this address
    has no backup.
    Returns a list of human-readable problems (empty == acceptable).
    """
    problems = []
    unavailable = set(retired_ips) | {ip}
    names = names_holding_ip(records, ip)
    if not names:
        problems.append(f"{ip}: 当前区域没有任何名称的 A 记录指向该地址，无法发起退役")
    for name in names:
        backups = [a for a in records[name]["A"] if a not in unavailable]
        if not backups:
            problems.append(
                f"{name}: 指向 {ip} 的名称没有未退役的备用 A 记录，退役会导致该名称无可用地址"
            )
    return problems


def publish_retirement_problems(candidate, retirements, now):
    """Whole-version checks imposed by committed retirements.

    - a deadline already passed: the address may not appear anywhere in
      the submission (no A record may carry it);
    - before the deadline: every name that pointed at the address in the
      version at retirement time must keep that exact name set, and each
      such name must keep at least one not-retired backup A record.
    """
    problems = []
    for r in retirements:
        ip, deadline = r.ip, r.deadline
        unavailable = set(r.other_retired_ips) | {ip}
        names = names_holding_ip(r.snapshot_records, ip)
        candidate_names = names_holding_ip(candidate, ip)
        if deadline <= now:
            if candidate_names:
                problems.append(
                    f"{ip}: 该地址已于 {r.deadline_text()} 到期退役，整版提交中不得再出现该地址"
                )
            continue
        if sorted(candidate_names) != names:
            problems.append(
                f"{ip}: 退役到期前，整版发布必须保持该地址对应的名称集合"
                f"（应为 {', '.join(names)}，实际 {', '.join(candidate_names) or '无'}）"
            )
        for name in names:
            rec = candidate.get(name)
            backups = [a for a in (rec["A"] if rec else []) if a not in unavailable]
            if not backups:
                problems.append(
                    f"{name}: 退役到期前必须为该名称保留至少一个未退役的备用 A 记录"
                )
    return problems


class Retirement:
    """One IPv4 address being decommissioned.

    The deadline is acceptance time + the largest TTL ever published for
    the address. Until the deadline the address keeps answering, with every
    A TTL capped to the remaining whole seconds; afterwards it is removed.
    """

    __slots__ = ("ip", "deadline", "max_ttl", "created_at",
                 "snapshot_records", "other_retired_ips")

    def __init__(self, ip, deadline, max_ttl, created_at,
                 snapshot_records=None, other_retired_ips=frozenset()):
        self.ip = ip
        self.deadline = float(deadline)
        self.max_ttl = int(max_ttl)
        self.created_at = created_at
        # frozen view of the version accepted at retirement time, so the
        # "keep the same name set" publish rule survives later versions
        self.snapshot_records = snapshot_records
        self.other_retired_ips = frozenset(other_retired_ips)

    def remaining(self, now):
        """Whole seconds until the deadline; floored at 0."""
        return max(0, math.ceil(self.deadline - now))

    def is_active(self, now):
        return now < self.deadline

    def deadline_text(self):
        return datetime.fromtimestamp(self.deadline, timezone.utc).isoformat(timespec="seconds")

    def to_dict(self, now):
        return {
            "ip": self.ip,
            "deadline": self.deadline_text(),
            "max_ttl": self.max_ttl,
            "accepted_at": self.created_at,
            "active": self.is_active(now),
            "remaining_seconds": self.remaining(now),
        }


class View:
    """Immutable combination of one published Snapshot and the committed
    retirement state. A DNS query captures a single View and resolves its
    whole chain against it, so a response never mixes zones and retirement
    states from two submissions."""

    __slots__ = ("snapshot", "retirements")

    def __init__(self, snapshot, retirements):
        self.snapshot = snapshot
        self.retirements = tuple(retirements)

    def active_for(self, now):
        return [r for r in self.retirements if r.is_active(now)]

    def to_dict(self, now):
        return [r.to_dict(now) for r in self.retirements]


class Snapshot:
    """Immutable view of one published version. A query resolves its whole
    alias chain against the single Snapshot instance captured at query start,
    so the chain and the final A address always come from the same version."""

    __slots__ = ("version_id", "created_at", "records")

    def __init__(self, version_id, created_at, records):
        self.version_id = version_id
        self.created_at = created_at
        # freeze: A lists become tuples, structure is never mutated afterwards
        self.records = {
            name: {"A": tuple(rec["A"]), "CNAME": rec["CNAME"], "ttl": rec["ttl"]}
            for name, rec in records.items()
        }

    def zone_text(self):
        lines = []
        for name in sorted(self.records):
            rec = self.records[name]
            for ip in rec["A"]:
                lines.append(f"{name} A {ip} {rec['ttl']}")
            if rec["CNAME"]:
                lines.append(f"{name} CNAME {rec['CNAME']} {rec['ttl']}")
        return "\n".join(lines)


def snapshot_from_rows(version_id, created_at, rows):
    """Rebuild a Snapshot from stored rows (name, rtype, value, ttl)."""
    records = {}
    for name, rtype, value, ttl in rows:
        rec = records.setdefault(name, {"A": [], "CNAME": None, "ttl": ttl})
        if rtype == "A":
            rec["A"].append(value)
        else:
            rec["CNAME"] = value
    return Snapshot(version_id, created_at, records)


class ViewHolder:
    """Atomically-swapped reference to the current committed View (zone
    snapshot + retirement state).

    Every publish and every retirement swaps the reference only after the
    SQLite transaction has committed; in-flight queries keep using the view
    they captured, so service never pauses and never mixes submissions."""

    def __init__(self):
        self._lock = threading.Lock()
        self._view = None

    def get(self):
        with self._lock:
            return self._view

    def set(self, view):
        with self._lock:
            self._view = view


def resolve(view, qname, qtype, now=None):
    """Resolve qname/qtype against one committed View.

    Returns (rcode, answers) where answers is a list of
    (name, rtype, value, ttl). qtype is a mnemonic: A, CNAME, ANY, ...

    Retirement semantics, applied from the single view captured at query
    start:
      - addresses whose deadline has passed are removed from every A set;
      - while a deadline is pending, the TTL of the whole A set at every
        node (including A reached through a CNAME chain) is capped to the
        smallest remaining whole seconds of the retirements touching it;
      - CNAME TTLs are untouched.
    """
    if now is None:
        now = time.time()
    qname = qname.lower()
    if qname != ZONE and not qname.endswith("." + ZONE):
        return "REFUSED", []

    snapshot = view.snapshot
    active = view.active_for(now)
    by_ip = {}
    for r in active:
        by_ip.setdefault(r.ip, []).append(r)
    expired = {r.ip for r in view.retirements if not r.is_active(now)}

    answers = []
    node = qname
    seen = set()
    while True:
        rec = snapshot.records.get(node)
        if rec is None:
            if answers:
                # A validated version never dangles; degrade gracefully.
                return "NOERROR", answers
            if node == ZONE:
                return "NOERROR", []  # zone apex exists but holds no such data
            return "NXDOMAIN", []
        if rec["CNAME"]:
            if node in seen:  # corrupt data safeguard; validated zones never loop
                return "NOERROR", answers
            seen.add(node)
            answers.append((node, "CNAME", rec["CNAME"], rec["ttl"]))
            if qtype == "CNAME":
                return "NOERROR", answers
            node = rec["CNAME"]
            continue
        if rec["A"]:
            if qtype in ("A", "ANY"):
                ips = [ip for ip in rec["A"] if ip not in expired]
                cap = min(
                    (by_ip[ip][0].remaining(now) for ip in ips if ip in by_ip),
                    default=None,
                )
                ttl = rec["ttl"] if cap is None else min(rec["ttl"], cap)
                answers.extend((node, "A", ip, ttl) for ip in ips)
            return "NOERROR", answers
        return "NOERROR", answers  # pragma: no cover
