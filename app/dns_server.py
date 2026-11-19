"""UDP authoritative DNS server for svc.test., backed by the view holder.

Each request captures the current committed View once (zone snapshot plus
retirement state) and resolves its entire alias chain against it, so a
response never mixes data from two submissions. Publishing or retiring
never blocks or interrupts serving: the swap is a reference assignment and
old views stay alive for in-flight queries."""

from dnslib import A, CNAME, QTYPE, RCODE, RR
from dnslib.server import BaseResolver, DNSServer

from .zone import resolve


class ZoneResolver(BaseResolver):
    def __init__(self, get_view):
        self._get_view = get_view

    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).lower()
        try:
            qtype = QTYPE[request.q.qtype]
        except KeyError:
            qtype = "UNKNOWN"

        view = self._get_view()  # captured once: one committed state per answer
        if view is None or view.snapshot is None:
            reply.header.rcode = RCODE.SERVFAIL  # nothing published yet
            return reply

        rcode, answers = resolve(view, qname, qtype)
        reply.header.rcode = getattr(RCODE, rcode)
        if rcode in ("NOERROR", "NXDOMAIN"):
            reply.header.aa = 1
        for name, rtype, value, ttl in answers:
            rdata = CNAME(value) if rtype == "CNAME" else A(value)
            reply.add_answer(
                RR(rname=name, rtype=getattr(QTYPE, rtype), rclass=1, ttl=ttl, rdata=rdata)
            )
        return reply


def start_dns_server(get_view, host, port):
    server = DNSServer(ZoneResolver(get_view), port=port, address=host, tcp=False)
    server.start_thread()  # dnslib marks the thread as daemon
    return server
