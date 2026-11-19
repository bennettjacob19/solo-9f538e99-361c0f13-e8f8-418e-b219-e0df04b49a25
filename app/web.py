"""FastAPI operations UI: publish full zone versions, retire IPv4
addresses, view the current version and retirement deadlines, and issue
real DNS queries against the running UDP server."""

import html
import sys
import time
from datetime import datetime, timezone

import ipaddress
import dnslib
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, RedirectResponse

from .deps import runtime
from .zone import (
    Retirement,
    Snapshot,
    View,
    ZoneError,
    flatten_records,
    fqdn,
    parse_zone_text,
    publish_retirement_problems,
    retirement_problems,
)

app = FastAPI(title="svc.test. zone publisher", docs_url=None, redoc_url=None)

PAGE = """<!doctype html>
<html><head><meta charset="utf-8"><title>{title}</title>
<style>
 body {{ font-family: system-ui, sans-serif; margin: 2rem auto; max-width: 960px; color: #222; }}
 h1 {{ font-size: 1.4rem; }} h2 {{ font-size: 1.1rem; margin-top: 2rem; }}
 table {{ border-collapse: collapse; }} td, th {{ border: 1px solid #ccc; padding: 4px 10px; }}
 textarea {{ width: 100%; font-family: ui-monospace, monospace; }}
 input[type=text] {{ width: 24rem; }}
 select {{ max-width: 18rem; }}
 .ok {{ background: #e6f7e6; border: 1px solid #8c8; padding: .6rem; }}
 .err {{ background: #fde8e8; border: 1px solid #c88; padding: .6rem; white-space: pre-wrap; }}
 .muted {{ color: #777; font-size: .9rem; }}
 .active {{ background: #fff4d6; }} .expired {{ background: #eee; color: #777; }}
 code {{ background: #f2f2f2; padding: 0 4px; }}
</style></head><body>
<h1>svc.test. 区域发布 <span class="muted">zone publisher</span></h1>
{body}
</body></html>"""


def esc(s):
    return html.escape(str(s), quote=True)


def page(body, title="svc.test. zone publisher", status_code=200):
    return HTMLResponse(PAGE.format(title=esc(title), body=body), status_code=status_code)


def current_view():
    return runtime.holder.get()


def failure_page(exc, action):
    """500 page used when the database cannot be read or written: the
    in-memory committed state keeps serving, nothing changes."""
    print(f"{action} failed: {exc!r}", file=sys.stderr)
    body = (f"<div class='err'>写入失败（{esc(type(exc).__name__)}: {esc(exc)}），\n"
            f"{action}未生效，当前版本与退役状态继续保持原状。</div>"
            "<p><a href='/'>返回</a></p>")
    return page(body, title="写入失败", status_code=500)


def versions_table():
    rows = []
    for v in runtime.store.list_versions():
        mark = " ✅ current" if v["current"] else ""
        rows.append(
            f"<tr><td>{v['id']}</td><td>{esc(v['created_at'])}</td>"
            f"<td>{v['records']}</td><td>{esc(v['note'])}{mark}</td></tr>"
        )
    if not rows:
        return "<p class='muted'>尚未发布任何版本。</p>"
    return ("<table><tr><th>版本</th><th>发布时间 (UTC)</th><th>记录数</th><th>备注</th></tr>"
            + "".join(rows) + "</table>")


def records_table(view):
    snap = view.snapshot if view is not None else None
    if snap is None:
        return "<p class='muted'>当前没有已发布版本。</p>"
    now = time.time()
    active = {r.ip: r for r in view.retirements if r.is_active(now)}
    expired = {r.ip for r in view.retirements if not r.is_active(now)}
    rows = []
    for name in sorted(snap.records):
        rec = snap.records[name]
        for ip in rec["A"]:
            tag = ""
            if ip in active:
                r = active[ip]
                tag = (f" <span class='active'>退役中：截止 {esc(r.deadline_text())}"
                       f"（剩余 {r.remaining(now)}s）</span>")
            elif ip in expired:
                tag = " <span class='expired'>已到期，新查询已摘除</span>"
            rows.append(
                f"<tr><td>{esc(name)}</td><td>A</td><td>{esc(ip)}</td>"
                f"<td>{rec['ttl']}</td><td>{tag}</td></tr>"
            )
        if rec["CNAME"]:
            rows.append(
                f"<tr><td>{esc(name)}</td><td>CNAME</td><td>{esc(rec['CNAME'])}</td>"
                f"<td>{rec['ttl']}</td><td></td></tr>"
            )
    body = "".join(rows) or "<tr><td colspan=5 class='muted'>(空区域)</td></tr>"
    return ("<table><tr><th>名称</th><th>类型</th><th>值</th><th>TTL</th>"
            "<th>退役状态</th></tr>" + body + "</table>")


def retirements_table(view):
    if view is None or not view.retirements:
        return "<p class='muted'>当前没有进行中的退役。</p>"
    now = time.time()
    rows = []
    for r in sorted(view.retirements, key=lambda x: x.deadline):
        if r.is_active(now):
            state = (f"<span class='active'>退役中，剩余 {r.remaining(now)} 秒</span>")
        else:
            state = "<span class='expired'>已到期，新查询自动摘除</span>"
        rows.append(
            f"<tr><td>{esc(r.ip)}</td><td>{esc(r.deadline_text())}</td>"
            f"<td>{r.max_ttl}</td><td>{esc(r.created_at)}</td><td>{state}</td></tr>"
        )
    return ("<table><tr><th>IPv4</th><th>截止时间 (UTC)</th><th>采用的最大历史 TTL</th>"
            "<th>受理时刻 (UTC)</th><th>状态</th></tr>" + "".join(rows) + "</table>")


def retire_form(view):
    snap = view.snapshot if view is not None else None
    if snap is None:
        return "<p class='muted'>请先发布一个版本，再从现行区域选择地址发起退役。</p>"
    ips = sorted({ip for rec in snap.records.values() for ip in rec["A"]})
    if not ips:
        return "<p class='muted'>当前区域没有任何 A 记录，无可退役的 IPv4。</p>"
    options = "".join(f"<option value='{esc(ip)}'>{esc(ip)}</option>" for ip in ips)
    return f"""
<form method="post" action="/retire">
  <p class="muted">从现行区域选择一个 IPv4 发起退役。指向它的每个名称都必须保留至少一个
  未退役的备用 A；截止时间 = 受理时刻 + 该地址历次已发布 A 记录中的最大 TTL。
  重复发起同一地址沿用原截止时间。</p>
  <select name="ip">{options}</select>
  <button type="submit">发起退役</button>
</form>"""


def index_body(msg="", err=""):
    view = current_view()
    snap = view.snapshot if view is not None else None
    banner = ""
    if msg:
        banner += f"<div class='ok'>{esc(msg)}</div>"
    if err:
        banner += f"<div class='err'>{esc(err)}</div>"
    if snap is None:
        version_info = "<p><b>当前版本:</b> 无（DNS 对区域内查询返回 SERVFAIL）</p>"
        prefill = "web A 10.0.0.1 60\napp CNAME web\n"
    else:
        version_info = (
            f"<p><b>当前版本:</b> v{snap.version_id} "
            f"<span class='muted'>发布于 {esc(snap.created_at)}</span></p>"
        )
        prefill = snap.zone_text()
    return f"""
{banner}
<h2>当前版本记录</h2>
{version_info}
{records_table(view)}

<h2>IPv4 退役（旧后端摘除）</h2>
{retire_form(view)}
{retirements_table(view)}

<h2>发起真实查询（UDP → 本机权威 DNS）</h2>
<form method="get" action="/query">
  <input type="text" name="name" placeholder="web 或 web.svc.test." required>
  <select name="qtype">
    <option>A</option><option>CNAME</option><option>ANY</option>
  </select>
  <button type="submit">查询</button>
</form>

<h2>发布新版（整版提交，校验/写入任一失败则整版拒绝）</h2>
<form method="post" action="/publish">
  <p class="muted">每行一条：<code>名称 A|CNAME 值 [TTL]</code>，# 为注释。
  CNAME 只能指向本区域内已定义的名称，循环或悬空将整版拒绝。
  退役到期前须保持地址对应的名称集合并为每个名称保留未退役备用 A；到期后该地址禁止再出现。</p>
  <textarea name="zone_text" rows="12">{esc(prefill)}</textarea>
  <p><input type="text" name="note" placeholder="备注（可选）"></p>
  <button type="submit">校验并发布</button>
</form>

<h2>版本历史</h2>
{versions_table()}
"""


@app.get("/", response_class=HTMLResponse)
def index(msg: str = ""):
    return page(index_body(msg=msg))


def _build_next_view(snapshot, prior_view):
    """Pair a new snapshot with Retirement objects bound to it.

    Each retirement keeps the snapshot records captured when it was accepted
    (the name-set rule is checked against that version), while the live
    answer filtering/capping always runs against the newest snapshot."""
    prior = prior_view.retirements if prior_view is not None else ()
    retirements = []
    retired_ips = {r.ip for r in prior}
    for r in prior:
        retirements.append(
            Retirement(
                r.ip, r.deadline, r.max_ttl, r.created_at,
                snapshot_records=r.snapshot_records,
                other_retired_ips=frozenset(retired_ips - {r.ip}),
            )
        )
    return View(snapshot, retirements)


@app.post("/publish", response_class=HTMLResponse)
def publish(zone_text: str = Form(...), note: str = Form("")):
    # 1) validate the whole candidate version; reject entirely on any problem
    try:
        parsed = parse_zone_text(zone_text)
    except ZoneError as exc:
        body = ("<div class='err'>校验失败，整版已拒绝，当前版本不受影响：\n"
                + esc("\n".join(exc.errors)) + "</div>"
                + "<p><a href='/'>返回</a></p>")
        return page(body, title="校验失败", status_code=400)

    # Retirements and publishes share one lock: they take effect strictly in
    # submission order, and each query sees one fully committed View.
    with runtime.operation_lock:
        prior_view = current_view()
        now = time.time()
        prior_rets = prior_view.retirements if prior_view is not None else ()
        problems = publish_retirement_problems(parsed, prior_rets, now)
        if problems:
            body = ("<div class='err'>退役约束校验失败，整版已拒绝，当前版本不受影响：\n"
                    + esc("\n".join(problems)) + "</div>"
                    + "<p><a href='/'>返回</a></p>")
            return page(body, title="退役约束拒绝", status_code=400)

        rows = flatten_records(parsed)
        # 2) single atomic transaction; on write failure the old state stays
        try:
            vid, created = runtime.store.publish(rows, note=note.strip())
        except Exception as exc:  # sqlite3.Error or IO failure
            return failure_page(exc, "整版发布")
        # 3) commit succeeded: swap the in-memory view for new queries
        snapshot = Snapshot(vid, created, parsed)
        runtime.holder.set(_build_next_view(snapshot, prior_view))
    return RedirectResponse(url=f"/?msg=已发布版本+v{vid}", status_code=303)


@app.post("/retire", response_class=HTMLResponse)
def retire(ip: str = Form(...)):
    ip = (ip or "").strip()
    with runtime.operation_lock:
        view = current_view()
        snap = view.snapshot if view is not None else None
        if snap is None:
            body = ("<div class='err'>当前没有已发布版本，无法发起退役。</div>"
                    "<p><a href='/'>返回</a></p>")
            return page(body, title="无法退役", status_code=400)

        try:
            norm_ip = str(ipaddress.IPv4Address(ip))
        except ValueError:
            body = (f"<div class='err'>{esc(ip)} 不是合法 IPv4 地址。</div>"
                    "<p><a href='/'>返回</a></p>")
            return page(body, title="无法退役", status_code=400)

        # idempotency comes first: a repeat (or restart-then-retry) request
        # for an address with an existing retirement — even one whose
        # deadline has passed — reuses the original deadline and never
        # re-validates against the current zone or writes a second row
        try:
            existing = runtime.store.get_retirement(norm_ip)
        except Exception as exc:
            return failure_page(exc, "退役受理")
        if existing is not None:
            prior = Retirement(
                existing["ip"], existing["deadline"], existing["max_ttl"],
                existing["created_at"],
            )
            return RedirectResponse(
                url=f"/?msg=地址+{prior.ip}+已在退役中，沿用原截止时间+{prior.deadline_text()}",
                status_code=303,
            )

        retired_ips = {r.ip for r in view.retirements}
        problems = retirement_problems(snap.records, norm_ip, retired_ips)
        if problems:
            body = ("<div class='err'>退役请求被拒绝，当前版本不受影响：\n"
                    + esc("\n".join(problems)) + "</div>"
                    + "<p><a href='/'>返回</a></p>")
            return page(body, title="退役拒绝", status_code=400)

        try:
            max_ttl = runtime.store.max_published_a_ttl(norm_ip)
        except Exception as exc:
            return failure_page(exc, "退役受理")
        now = time.time()
        deadline = now + max_ttl
        created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        try:
            runtime.store.insert_retirement(norm_ip, deadline, max_ttl, created_at)
        except Exception as exc:
            # write failure: nothing changes, the old view keeps serving
            return failure_page(exc, "退役受理")

        retirement = Retirement(
            norm_ip, deadline, max_ttl, created_at,
            snapshot_records=snap.records,
            other_retired_ips=frozenset(retired_ips),
        )
        runtime.holder.set(View(snap, tuple(view.retirements) + (retirement,)))
    return RedirectResponse(
        url=f"/?msg=已受理+{norm_ip}+退役，截止时间+{retirement.deadline_text()}",
        status_code=303,
    )


@app.get("/query", response_class=HTMLResponse)
def query(name: str = "", qtype: str = "A"):
    qtype = qtype.upper()
    if qtype not in ("A", "CNAME", "ANY"):
        return page("<div class='err'>仅支持 A / CNAME / ANY 查询</div><p><a href='/'>返回</a></p>",
                    status_code=400)
    try:
        qname = fqdn(name)
    except ValueError:
        qname = name.strip().lower().rstrip(".") + "."  # let the server REFUSE it
    try:
        pkt = dnslib.DNSRecord.question(qname, qtype).send(
            runtime.dns_query_host, runtime.dns_query_port, timeout=3
        )
        resp = dnslib.DNSRecord.parse(pkt)
    except Exception as exc:
        body = f"<div class='err'>查询失败: {esc(exc)}</div><p><a href='/'>返回</a></p>"
        return page(body, title="查询失败", status_code=502)

    rcode = dnslib.RCODE[resp.header.rcode]
    lines = [f";; ->>HEADER<<- rcode: {rcode}, aa: {resp.header.aa}"]
    for rr in resp.rr:
        lines.append(f"{rr.rname} {rr.ttl} IN {dnslib.QTYPE[rr.rtype]} {rr.rdata}")
    if not resp.rr:
        lines.append(";; (no answer records)")
    body = (f"<h2>查询 {esc(qname)} {qtype}</h2><pre>{esc(chr(10).join(lines))}</pre>"
            "<p><a href='/'>返回</a></p>")
    return page(body, title=f"query {qname}")


@app.get("/api/current")
def api_current():
    view = current_view()
    snap = view.snapshot if view is not None else None
    if snap is None:
        return {"version": None, "records": []}
    records = []
    for name in sorted(snap.records):
        rec = snap.records[name]
        for ip in rec["A"]:
            records.append({"name": name, "type": "A", "value": ip, "ttl": rec["ttl"]})
        if rec["CNAME"]:
            records.append({"name": name, "type": "CNAME", "value": rec["CNAME"], "ttl": rec["ttl"]})
    return {"version": snap.version_id, "created_at": snap.created_at, "records": records}


@app.get("/api/versions")
def api_versions():
    return runtime.store.list_versions()


@app.get("/api/retirements")
def api_retirements():
    view = current_view()
    if view is None:
        return {"retirements": []}
    return {"retirements": view.to_dict(time.time())}
