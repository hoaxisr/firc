#!/usr/bin/env python3
"""HTTP contract driver: runs a fixed request sequence against fircd and prints a canonical trace."""
import http.client
import http.server
import json
import socket
import sys
import threading
import time

STUB_SUB_PORT = 18099
STUB_SUB_URL = "http://127.0.0.1:%d/list.txt" % STUB_SUB_PORT
STUB_TUN_URL = "http://127.0.0.1:%d/tunnels-sub.txt?token=fake" % STUB_SUB_PORT
FAKE_UUID = "00000000-0000-4000-8000-000000000001"
TUN_SUB_BODY = "".join(
    "vless://%s@%s.example.invalid:443?security=none#%s\n" % (FAKE_UUID, n.lower(), n)
    for n in ("NL-1", "NL-2", "DE-1")
).encode("utf-8")
TUN_LINK = "vless://%s@a.example.invalid:443?security=none#A" % FAKE_UUID


class _StubSubListHandler(http.server.BaseHTTPRequestHandler):
    """Serves a fixed list so the sync and preview steps trace the same every run."""

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if self.path == "/list.txt":
            body = b"one.example\ntwo.example"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/tunnels-sub.txt"):
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(TUN_SUB_BODY)))
            self.end_headers()
            self.wfile.write(TUN_SUB_BODY)
        else:
            self.send_response(404)
            self.end_headers()


def start_stub_sub_server():
    server = http.server.HTTPServer(("127.0.0.1", STUB_SUB_PORT), _StubSubListHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


_LIVE_TS_KEYS = ("lastUpdate", "lastCheck")

_VOLATILE_KEYS = ("since", "backoffS", "lastExit", "rxBps", "txBps", "lastOk", "lastTry")


def _redact_live_timestamps(obj):
    """Replaces non-zero lastUpdate/lastCheck values and every live tunnel figure with a placeholder."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in _LIVE_TS_KEYS and isinstance(v, (int, float)) and v != 0:
                out[k] = "<TS>"
            elif k in _VOLATILE_KEYS and isinstance(v, (int, float)):
                out[k] = "<LIVE>"
            else:
                out[k] = _redact_live_timestamps(v)
        return out
    if isinstance(obj, list):
        return [_redact_live_timestamps(x) for x in obj]
    return obj


def wait_settled(conn, group_id, tries=400):
    """Polls untraced until the group's list settles; returns its state, None if gone, raises otherwise."""
    last = None
    for _ in range(tries):
        status, data = request(conn, "GET", "/api/v1/groups")
        # A non-200 or non-list answer means the daemon is not answering: fail, do not trace it.
        if status != 200:
            raise RuntimeError(
                "GET /api/v1/groups answered %s while waiting for %s to settle"
                % (status, group_id)
            )
        try:
            obj = json.loads(data.decode("utf-8")) if data else None
        except ValueError:
            obj = None
        if not isinstance(obj, dict) or not isinstance(obj.get("groups"), list):
            raise RuntimeError(
                "GET /api/v1/groups is not a group list while waiting for "
                "%s to settle: %r" % (group_id, data[:200])
            )
        found = False
        for rec in obj["groups"]:
            if rec.get("id") == group_id:
                found = True
                last = ((rec.get("list") or {}).get("sync") or {}).get("state")
                if last not in ("queued", "fetching"):
                    return last
        if not found:
            # Gone is settled: a DELETE mid-sync ends the job.
            return None
        time.sleep(0.05)
    raise RuntimeError(
        "group %s did not settle in %.0f s: list.sync.state is %r"
        % (group_id, tries * 0.05, last)
    )


def wait_tunnel_ready(conn, tunnel_id, tries=400):
    last = None
    for _ in range(tries):
        status, data = request(conn, "GET", "/api/v1/tunnels/state")
        if status != 200:
            raise RuntimeError("GET /api/v1/tunnels/state answered %s" % status)
        obj = json.loads(data.decode("utf-8"))
        for rec in obj.get("tunnels") or []:
            if rec.get("id") != tunnel_id:
                continue
            subs = rec.get("subscriptions") or []
            last = (rec.get("status"), [x.get("lastOk") for x in subs])
            if rec.get("status") == "up" and subs and all(x.get("lastOk") for x in subs):
                return
        time.sleep(0.05)
    raise RuntimeError("tunnel %s not ready in %.0f s: %r" % (tunnel_id, tries * 0.05, last))


def run_tunnel_sequence(t, conn):
    t.step("GET", "/api/v1/tunnels")
    t.step("PUT", "/api/v1/tunnels", "{}")
    t.step("PUT", "/api/v1/tunnels", json.dumps({"tunnels": [{"id": "t1", "device": "eth0", "enable": False}]}))
    tunnels = {
        "tunnels": [
            {
                "id": "t1",
                "device": "tunvless0",
                "description": "PRAW-1",
                "sources": [
                    {"id": "0000000a", "kind": "link", "link": TUN_LINK},
                    {"id": "0000000b", "kind": "subscription", "name": "Stub", "url": STUB_TUN_URL,
                     "interval": 3600},
                ],
                "filter": "^(A|NL-.*)$",
                "order": ["0000000b:NL-2"],
                "exclude": ["0000000b:NL-1"],
            },
            {
                "id": "t2",
                "device": "tunvless1",
                "enable": False,
                "uplink": {"kind": "tunnel", "ref": "t1"},
                "sources": [{"id": "0000000c", "kind": "link", "link": TUN_LINK}],
            },
        ]
    }
    t.step("PUT", "/api/v1/tunnels", json.dumps(tunnels))
    wait_tunnel_ready(conn, "t1")
    t.step("GET", "/api/v1/tunnels")
    t.step("GET", "/api/v1/tunnels/state")
    draft = dict(tunnels["tunnels"][0], filter="^(NL|DE)-", exclude=[], order=["0000000b:DE-1"])
    t.step("POST", "/api/v1/tunnels/preview", json.dumps({"tunnel": draft}))
    t.step("POST", "/api/v1/tunnels/preview", json.dumps({"tunnel": dict(draft, filter="(")}))
    t.step("POST", "/api/v1/tunnels/probe", json.dumps({"id": "t1"}))
    t.step("POST", "/api/v1/tunnels/probe", json.dumps({"id": "zz"}))
    t.step("POST", "/api/v1/tunnels/t1/refresh")
    t.step("POST", "/api/v1/tunnels/t2/refresh")
    t.step("POST", "/api/v1/tunnels/zz/refresh")
    t.step("POST", "/api/v1/tunnels/t2/restart")
    t.step("POST", "/api/v1/tunnels/zz/restart")
    t.step("POST", "/api/v1/tunnels/t1/restart")
    t.step("PUT", "/api/v1/tunnels", json.dumps({"tunnels": []}))
    t.step("GET", "/api/v1/tunnels/state")


def _normalize_host_interfaces(obj):
    """Preserve the response contract without freezing runner device names."""
    if not isinstance(obj, dict) or set(obj.keys()) != {"interfaces"}:
        return obj
    interfaces = obj["interfaces"]
    if (
        not isinstance(interfaces, list)
        or len(interfaces) < 2
        or interfaces[0] != {"id": "blackhole"}
        or not all(isinstance(item, dict) and isinstance(item.get("id"), str) for item in interfaces)
    ):
        return obj
    return {"interfaces": [{"id": "blackhole"}, {"id": "<HOST-INTERFACES>"}]}


class UnixHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection over an AF_UNIX socket."""

    def __init__(self, path):
        super().__init__("localhost")
        self._unix_path = path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self._unix_path)
        self.sock = sock


def request(conn, method, path, body=None):
    headers = {"Content-Type": "application/json"} if body is not None else {}
    conn.request(method, path, body=body, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    return resp.status, data


class Trace:
    """One run's trace, with learned ids and error text redacted."""

    def __init__(self, conn, out):
        self.conn = conn
        self.out = out
        self.n = 0
        self.replacements = {}  # real id string -> "<PLACEHOLDER>"

    def _learn(self, real_id, placeholder):
        if real_id and real_id not in self.replacements:
            self.replacements[real_id] = placeholder

    def _redact(self, text):
        for real, placeholder in self.replacements.items():
            text = text.replace(real, placeholder)
        return text

    def _canonical(self, obj):
        if obj is None:
            return "<empty>"
        if isinstance(obj, dict) and set(obj.keys()) == {"error"}:
            obj = {"error": "<ERR>"}
        # Live sync timestamps differ per run; 0 (never synced) is kept.
        obj = _redact_live_timestamps(obj)
        return self._redact(json.dumps(obj, sort_keys=True, separators=(",", ":")))

    def step(self, method, path, body=None, learn=None, normalize=None):
        """Runs one traced step; learn() ids are redacted before this step prints."""
        self.n += 1
        status, data = request(self.conn, method, path, body)
        try:
            parsed = json.loads(data.decode("utf-8")) if data else None
        except ValueError:
            parsed = None
        if normalize:
            parsed = normalize(parsed)
        if learn:
            for real_id, placeholder in learn(parsed):
                self._learn(real_id, placeholder)

        self.out.write("STEP %d %s %s\n" % (self.n, method, self._redact(path)))
        if body is not None:
            raw = body.encode("utf-8") if isinstance(body, str) else body
            try:
                req_obj = json.loads(raw.decode("utf-8")) if raw else None
            except ValueError:
                req_obj = None
            self.out.write("REQBODY %s\n" % self._canonical(req_obj))
        self.out.write("STATUS %d\n" % status)
        self.out.write("BODY %s\n" % self._canonical(parsed))
        self.out.write("---\n")
        return status, parsed

    def sse_step(self, path):
        """Traces an event-stream route as the ordered list of event names."""
        self.n += 1
        status, data = request(self.conn, "GET", path)
        if status == 200:
            body = {
                "events": [
                    line[len("event: ") :]
                    for line in data.decode("utf-8", "replace").split("\n")
                    if line.startswith("event: ")
                ]
            }
        else:
            # A refusal is an ordinary JSON answer, printed as one.
            try:
                body = json.loads(data.decode("utf-8")) if data else None
            except ValueError:
                body = None
        self.out.write("STEP %d GET %s\n" % (self.n, self._redact(path)))
        self.out.write("STATUS %d\n" % status)
        self.out.write("BODY %s\n" % self._canonical(body))
        self.out.write("---\n")
        return status


def run_tcp_door(base_host, base_port, out):
    """WebUI listener with no session: status and login answer, everything else is 401."""
    conn = http.client.HTTPConnection(base_host, base_port, timeout=5)
    out.write("LISTENER tcp\n")
    t = Trace(conn, out)
    t.step("GET", "/api/v1/auth")
    t.step("GET", "/api/v1/groups")
    t.step("POST", "/api/v1/auth", json.dumps({"login": "nobody", "password": "nothing"}))
    conn.close()


def run_api_sequence(conn, out):
    """Unix-socket API sequence; prints its listener name so step numbers stay unambiguous."""
    out.write("LISTENER unix\n")
    t = Trace(conn, out)

    group_body = json.dumps(
        {
            "id": "aabbccdd",
            "name": "g1",
            "interface": "eth0",
            "enable": False,
            "rules": [{"type": "domain", "rule": "example.com", "enable": True}],
        }
    )
    t.step("POST", "/api/v1/groups", group_body,
          learn=lambda r: [(r["rules"][0]["id"], "<RULE-R1>")])

    t.step("GET", "/api/v1/groups?with_rules=true")
    t.step("GET", "/api/v1/groups/aabbccdd?with_rules=true")
    t.step("GET", "/api/v1/groups/nothex!")
    t.step("GET", "/api/v1/groups/deadbeef")

    put_group_body = json.dumps(
        {"name": "g1-renamed", "interface": "eth1", "enable": False}
    )
    t.step("PUT", "/api/v1/groups/aabbccdd", put_group_body)

    new_rule_body = json.dumps({"type": "wildcard", "rule": "*.example.org", "enable": True})
    rule_r2_holder = []

    def learn_rule_r2(resp):
        rule_r2_holder.append(resp["id"])
        return [(resp["id"], "<RULE-R2>")]

    t.step("POST", "/api/v1/groups/aabbccdd/rules", new_rule_body, learn=learn_rule_r2)
    rule_r2 = rule_r2_holder[0]

    t.step("GET", "/api/v1/groups/aabbccdd/rules")
    t.step("GET", "/api/v1/groups/aabbccdd/rules/" + rule_r2)

    put_rule_body = json.dumps(
        {"type": "wildcard", "rule": "*.example.net", "enable": False}
    )
    t.step("PUT", "/api/v1/groups/aabbccdd/rules/" + rule_r2, put_rule_body)
    t.step("DELETE", "/api/v1/groups/aabbccdd/rules/" + rule_r2)
    t.step("GET", "/api/v1/groups/aabbccdd/rules")
    t.step("GET", "/api/v1/groups/aabbccdd/rules/deadbeef")

    t.step("DELETE", "/api/v1/groups/aabbccdd")
    t.step("GET", "/api/v1/groups")

    bulk_body = json.dumps(
        {
            "groups": [
                {
                    "id": "10101010",
                    "name": "bulk-1",
                    "interface": "eth0",
                    "enable": False,
                    "rules": [{"type": "domain", "rule": "bulk.example.com", "enable": True}],
                },
                {"id": "30303030", "name": "bulk-2", "interface": "eth1", "enable": False},
            ]
        }
    )
    t.step("PUT", "/api/v1/groups", bulk_body,
          learn=lambda r: [(r["groups"][0]["rules"][0]["id"], "<RULE-BR1>")])
    t.step("GET", "/api/v1/groups?with_rules=true")
    t.step("PUT", "/api/v1/groups", "{}")

    t.step("GET", "/api/v1/system/interfaces", normalize=_normalize_host_interfaces)
    t.step("POST", "/api/v1/system/hooks/netfilterd", json.dumps({"type": "iptables", "table": "nat"}))
    t.step("POST", "/api/v1/system/config/save")

    # enable:false: a disabled group syncs nothing and builds no netfilter state on "eth0".
    t.step("GET", "/api/v1/groups")
    list_body = json.dumps(
        {"id": "40404040", "name": "s1", "interface": "eth0", "enable": False,
         "list": {"url": "https://example.com/list.txt"}}
    )
    t.step("POST", "/api/v1/groups", list_body)
    t.step("POST", "/api/v1/groups", list_body)  # duplicate id -> 409
    t.step("POST", "/api/v1/groups", json.dumps({"name": "no-url", "list": {}}))  # no url -> 400
    t.step("GET", "/api/v1/groups")

    def bulk_rule_id():
        # The real id behind <RULE-BR1>: a PUT that names a rule's id keeps it.
        for real, placeholder in t.replacements.items():
            if placeholder == "<RULE-BR1>":
                return real
        raise RuntimeError("the bulk rule id was never learned")

    put_list_body = json.dumps(
        {
            "groups": [
                {
                    "id": "10101010",
                    "name": "bulk-1",
                    "interface": "eth0",
                    "enable": False,
                    "rules": [{"id": bulk_rule_id(), "type": "domain", "rule": "bulk.example.com",
                               "enable": True}],
                },
                {"id": "30303030", "name": "bulk-2", "interface": "eth1", "enable": False},
                {"id": "40404040", "name": "s1-renamed", "enable": False,
                 "list": {"url": "https://example.com/list.txt"}},
            ]
        }
    )
    t.step("PUT", "/api/v1/groups", put_list_body)
    t.step("GET", "/api/v1/groups")
    t.step("PUT", "/api/v1/groups", "{}")  # missing key -> 400

    # Fetch-backed sync and preview against the local stub list server.
    def learn_preview_rule_ids(resp):
        if not resp:
            return []
        return [(r["id"], "<PREVIEWRULE-%d>" % i) for i, r in enumerate(resp.get("rules") or [])]

    t.step("GET", "/api/v1/groups/list/preview")  # missing url -> 400
    t.step("GET", "/api/v1/groups/list/preview?url=" + STUB_SUB_URL, learn=learn_preview_rule_ids)
    t.step("GET", "/api/v1/groups/list/preview?url=http://127.0.0.1:1/nope")  # connection refused -> 502

    def learn_sync_rule_ids(resp):
        if not resp:
            return []
        return [(r["id"], "<SUBRULE-%d>" % i) for i, r in enumerate(resp.get("rules") or [])]

    t.step("POST", "/api/v1/groups/deadbeef/list/sync")  # unknown id -> 404
    # 202: accepted, not finished; wait for it untraced.
    t.step("POST", "/api/v1/groups/40404040/list/sync", json.dumps({"url": STUB_SUB_URL}),
          learn=learn_sync_rule_ids)
    wait_settled(conn, "40404040")
    t.step("GET", "/api/v1/groups")
    t.step("POST", "/api/v1/groups/40404040/list/sync")  # re-sync, same content -> unchanged
    wait_settled(conn, "40404040")
    # A list with nothing running gets one event and a close.
    t.sse_step("/api/v1/groups/40404040/list/sync/events")
    t.sse_step("/api/v1/groups/deadbeef/list/sync/events")  # unknown id -> 404

    t.step("DELETE", "/api/v1/groups/40404040")
    t.step("DELETE", "/api/v1/groups/40404040")  # already gone -> 404
    t.step("GET", "/api/v1/groups")

    run_tunnel_sequence(t, conn)

    t.step("GET", "/api/v1/auth")


def main():
    if len(sys.argv) < 3:
        sys.stderr.write("usage: contract.py <host> <port> [unix_socket_path]\n")
        return 2
    host, port = sys.argv[1], int(sys.argv[2])
    if len(sys.argv) <= 3:
        sys.stderr.write("the Unix socket path is required: the API sequence runs there\n")
        return 2
    stub = start_stub_sub_server()
    try:
        run_tcp_door(host, port, sys.stdout)
        conn = UnixHTTPConnection(sys.argv[3])
        try:
            run_api_sequence(conn, sys.stdout)
        finally:
            conn.close()
    finally:
        stub.shutdown()
        stub.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
