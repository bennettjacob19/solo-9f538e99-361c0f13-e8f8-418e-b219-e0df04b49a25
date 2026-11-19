"""Shared runtime state, wired up once in main and used by web + DNS."""

import threading

from .zone import ViewHolder, ZONE


class Runtime:
    def __init__(self):
        self.store = None
        self.holder = ViewHolder()
        # One lock for both publishes and retirements: they take effect in
        # submission order, and each query reads one committed View.
        self.publish_lock = threading.Lock()
        self.zone = ZONE
        self.dns_query_host = "127.0.0.1"  # where the web UI sends real queries
        self.dns_query_port = 5353
        self.refresh_interval = 2.0  # seconds; DB re-sync safety net

    @property
    def operation_lock(self):
        return self.publish_lock


runtime = Runtime()
