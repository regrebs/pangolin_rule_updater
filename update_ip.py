"""
pangolin_rule_updater — multi-rule edition
==========================================
Manages one *or many* Pangolin bypass rules from a single container.

Single-rule (original) format — still works unchanged:
    API_KEY=...  RESOURCE_ID=1  RULE_ID=1  PANGOLIN_HOST=https://...

Multi-rule format — add as many numbered blocks as you need:
    RULE_1_API_KEY=...        RULE_1_RESOURCE_ID=1   RULE_1_RULE_ID=1
    RULE_1_PANGOLIN_HOST=...

    RULE_2_API_KEY=...        RULE_2_RESOURCE_ID=2   RULE_2_RULE_ID=3
    RULE_2_PANGOLIN_HOST=...  RULE_2_TARGET_DOMAIN=my.home.dyndns.org

Every RULE_N_ block inherits the global optional defaults (LOOP_SECONDS,
LOOP_JITTER, RULE_PRIORITY, RULE_ACTION, RULE_MATCH, RULE_ENABLED,
IP_SERVICE_URL) but can override each one individually.

The trigger-website feature (EXPOSE_TRIGGER_WEBSITE) is global and updates
ALL rules when a request arrives.
"""

import ipaddress
import os
import json
import random
import socket
import time
import threading
from dataclasses import dataclass, field
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()

# ── Global / shared optional settings ─────────────────────────────────────────

LOOP_SECONDS = int(os.environ.get("LOOP_SECONDS", "60"))
LOOP_JITTER  = int(os.environ.get("LOOP_JITTER",  "10"))

_DEFAULT_IP_SERVICES = "https://wtfismyip.com/text,https://api.ipify.org,https://icanhazip.com"
_GLOBAL_IP_SERVICE_URLS = [
    u.strip()
    for u in os.environ.get("IP_SERVICE_URL", _DEFAULT_IP_SERVICES).split(",")
    if u.strip()
]

EXPOSE_TRIGGER_WEBSITE = os.environ.get("EXPOSE_TRIGGER_WEBSITE", "False").lower() == "true"
if EXPOSE_TRIGGER_WEBSITE:
    TRIGGER_WEBSITE_DOMAIN = os.environ.get("TRIGGER_WEBSITE_DOMAIN", "trigger.my.dyn.dns.com")
    TRIGGER_WEBSITE_PATH   = os.environ.get("TRIGGER_WEBSITE_PATH",   "/update")
    TRIGGER_WEBSITE_PORT   = int(os.environ.get("TRIGGER_WEBSITE_PORT", "8080"))
    TRIGGER_SECRET         = os.environ.get("TRIGGER_SECRET", "")


# ── Per-rule configuration ─────────────────────────────────────────────────────

@dataclass
class RuleConfig:
    label: str                          # e.g. "rule-1" or "legacy"
    api_key: str
    resource_id: str
    rule_id: str
    pangolin_host: str
    target_domain: Optional[str]        # resolve this instead of own IP
    loop_seconds: int
    loop_jitter: int
    rule_priority: int
    rule_action: str
    rule_match: str
    rule_enabled: bool
    ip_service_urls: list
    session: requests.Session = field(default_factory=requests.Session)

    # mutable state
    cached_ip: Optional[str] = None
    ip_service_index: int = 0
    rule_fetch_failed_at: Optional[float] = None
    lock: threading.Lock = field(default_factory=threading.Lock)

    _RULE_FETCH_COOLDOWN = 60

    def __post_init__(self):
        if self.rule_match not in ("IP", "CIDR", "PATH"):
            raise ValueError(f"[{self.label}] Invalid RULE_MATCH: {self.rule_match!r}")
        self.session.headers.update({
            "accept": "*/*",
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (compatible; HTTPClient/1.0)",
        })

    # ── IP resolution ──────────────────────────────────────────────────────────

    def _get_target_ip(self) -> str:
        try:
            return socket.gethostbyname(self.target_domain)
        except socket.gaierror as e:
            raise Exception(f"[{self.label}] Failed to resolve {self.target_domain}: {e}")

    def _get_external_ip(self) -> str:
        url = self.ip_service_urls[self.ip_service_index % len(self.ip_service_urls)]
        self.ip_service_index += 1
        raw = self.session.get(url, timeout=5).text.strip()
        try:
            ipaddress.ip_address(raw)
        except ValueError:
            raise ValueError(f"[{self.label}] IP service returned invalid address: {raw!r}")
        return raw

    def get_current_ip(self) -> str:
        return self._get_target_ip() if self.target_domain else self._get_external_ip()

    # ── Pangolin API ───────────────────────────────────────────────────────────

    def fetch_rule_value(self) -> Optional[str]:
        url = f"{self.pangolin_host}/v1/resource/{self.resource_id}/rules?limit=1000&offset=0"
        resp = self.session.get(url, timeout=10)
        if resp.status_code != 200:
            print(f"[{self.label}][error] Fetch rules failed: {resp.status_code} {resp.text}")
            return None
        for rule in resp.json()["data"]["rules"]:
            if rule["ruleId"] == int(self.rule_id):
                return rule["value"]
        print(f"[{self.label}][info] Rule ID {self.rule_id} not found")
        return None

    def push_rule(self, new_ip: str) -> None:
        url = f"{self.pangolin_host}/v1/resource/{self.resource_id}/rule/{self.rule_id}"
        payload = {
            "action":   self.rule_action,
            "match":    self.rule_match,
            "value":    new_ip,
            "priority": self.rule_priority,
            "enabled":  self.rule_enabled,
        }
        resp = self.session.post(url, data=json.dumps(payload), timeout=10)
        if resp.status_code != 200:
            raise Exception(
                f"[{self.label}] Failed to update rule {self.rule_id}: "
                f"{resp.status_code} {resp.text}"
            )
        print(f"[{self.label}][pangolin] Rule {self.rule_id} updated → {new_ip}")


# ── Config loader ──────────────────────────────────────────────────────────────

def _env(key: str, default=None, prefix: str = "") -> Optional[str]:
    """Read RULE_N_KEY first, fall back to global KEY."""
    if prefix:
        val = os.environ.get(f"{prefix}{key}")
        if val is not None:
            return val
    return os.environ.get(key, default)


def load_rule_configs() -> list[RuleConfig]:
    configs: list[RuleConfig] = []

    # ── Discover numbered blocks: RULE_1_, RULE_2_, … ─────────────────────────
    numbered: dict[int, str] = {}  # index → prefix
    for key in os.environ:
        if key.startswith("RULE_") and key.endswith("_API_KEY"):
            middle = key[len("RULE_"):-len("_API_KEY")]
            if middle.isdigit():
                numbered[int(middle)] = f"RULE_{middle}_"

    if numbered:
        for idx in sorted(numbered):
            prefix = numbered[idx]
            label  = f"rule-{idx}"

            api_key     = os.environ.get(f"{prefix}API_KEY")
            resource_id = os.environ.get(f"{prefix}RESOURCE_ID")
            rule_id     = os.environ.get(f"{prefix}RULE_ID")
            host        = os.environ.get(f"{prefix}PANGOLIN_HOST",
                              os.environ.get("PANGOLIN_HOST", "https://api.pangolin.example"))

            if not all([api_key, resource_id, rule_id]):
                print(f"[warn] Skipping {label}: missing API_KEY / RESOURCE_ID / RULE_ID")
                continue

            ip_svc_raw = os.environ.get(f"{prefix}IP_SERVICE_URL",
                             os.environ.get("IP_SERVICE_URL", ",".join(_GLOBAL_IP_SERVICE_URLS)))
            ip_services = [u.strip() for u in ip_svc_raw.split(",") if u.strip()]

            cfg = RuleConfig(
                label         = label,
                api_key       = api_key,
                resource_id   = resource_id,
                rule_id       = rule_id,
                pangolin_host = host,
                target_domain = (os.environ.get(f"{prefix}TARGET_DOMAIN", "").strip() or None),
                loop_seconds  = int(os.environ.get(f"{prefix}LOOP_SECONDS",
                                    os.environ.get("LOOP_SECONDS", "60"))),
                loop_jitter   = int(os.environ.get(f"{prefix}LOOP_JITTER",
                                    os.environ.get("LOOP_JITTER",  "10"))),
                rule_priority = int(os.environ.get(f"{prefix}RULE_PRIORITY",
                                    os.environ.get("RULE_PRIORITY", "100"))),
                rule_action   = os.environ.get(f"{prefix}RULE_ACTION",
                                    os.environ.get("RULE_ACTION", "ACCEPT")).upper(),
                rule_match    = os.environ.get(f"{prefix}RULE_MATCH",
                                    os.environ.get("RULE_MATCH", "IP")).upper(),
                rule_enabled  = os.environ.get(f"{prefix}RULE_ENABLED",
                                    os.environ.get("RULE_ENABLED", "True")).lower() == "true",
                ip_service_urls = ip_services,
            )
            configs.append(cfg)
        return configs

    # ── Legacy single-rule (original env var names) ────────────────────────────
    api_key     = os.environ.get("API_KEY")
    resource_id = os.environ.get("RESOURCE_ID")
    rule_id     = os.environ.get("RULE_ID")

    if not all([api_key, resource_id, rule_id]):
        raise EnvironmentError(
            "No rule configuration found. "
            "Set API_KEY / RESOURCE_ID / RULE_ID for a single rule, "
            "or RULE_1_API_KEY / RULE_1_RESOURCE_ID / RULE_1_RULE_ID etc. for multiple rules."
        )

    configs.append(RuleConfig(
        label         = "legacy",
        api_key       = api_key,
        resource_id   = resource_id,
        rule_id       = rule_id,
        pangolin_host = os.environ.get("PANGOLIN_HOST", "https://api.pangolin.example"),
        target_domain = (os.environ.get("TARGET_DOMAIN", "").strip() or None),
        loop_seconds  = LOOP_SECONDS,
        loop_jitter   = LOOP_JITTER,
        rule_priority = int(os.environ.get("RULE_PRIORITY", "100")),
        rule_action   = os.environ.get("RULE_ACTION", "ACCEPT").upper(),
        rule_match    = os.environ.get("RULE_MATCH",  "IP").upper(),
        rule_enabled  = os.environ.get("RULE_ENABLED", "True").lower() == "true",
        ip_service_urls = _GLOBAL_IP_SERVICE_URLS,
    ))
    return configs


# ── Polling loop (one per rule) ────────────────────────────────────────────────

def run_polling_loop(cfg: RuleConfig) -> None:
    backoff = 5
    while True:
        try:
            current_ip = cfg.get_current_ip()
            with cfg.lock:
                if cfg.cached_ip is None or current_ip != cfg.cached_ip:
                    label = "Initial IP" if cfg.cached_ip is None else f"{cfg.cached_ip} →"
                    print(f"[{cfg.label}][info] {label} {current_ip}")
                    cfg.push_rule(current_ip)
                    cfg.cached_ip = current_ip
                else:
                    print(f"[{cfg.label}][info] IP unchanged ({current_ip})")
            backoff = 5
            jitter = random.uniform(-cfg.loop_jitter, cfg.loop_jitter)
            time.sleep(max(1, cfg.loop_seconds + jitter))
        except Exception as e:
            import traceback
            print(f"[{cfg.label}][error] {e}")
            traceback.print_exc()
            print(f"[{cfg.label}][info] Retrying in {backoff}s")
            time.sleep(backoff)
            backoff = min(backoff * 2, 300)


# ── Trigger website ────────────────────────────────────────────────────────────

_HTML_OK = """<html><head><title>IP Update Trigger</title></head><body>
<h1>IP Update Trigger</h1><p>Update triggered successfully.</p>
<p>New IP: {ip}</p><p>Rules updated: {rules}</p></body></html>"""

_HTML_NOK = """<html><head><title>IP Update Trigger</title></head><body>
<h1>IP Update Trigger</h1><p>Update could not be triggered.</p></body></html>"""

_HTML_NO_CHANGE = """<html><head><title>IP Update Trigger</title></head><body>
<h1>IP Update Trigger</h1><p>No change — IP is already up-to-date.</p></body></html>"""

_HTML_UNAUTHORIZED = """<html><head><title>IP Update Trigger</title></head><body>
<h1>IP Update Trigger</h1><p>Unauthorized.</p></body></html>"""

_RULE_FETCH_COOLDOWN = 60


def make_trigger_handler(rule_configs: list[RuleConfig]):
    """Return a handler class that closes over the shared rule list."""

    class TriggerHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            host   = self.headers.get("Host", "").split(":")[0]
            path   = parsed.path

            if path != TRIGGER_WEBSITE_PATH or host != TRIGGER_WEBSITE_DOMAIN:
                self._send(404, "<h1>Not Found</h1>")
                return

            if TRIGGER_SECRET:
                provided = parse_qs(parsed.query).get("token", [""])[0]
                if provided != TRIGGER_SECRET:
                    print("[warn] Unauthorized trigger attempt — bad or missing token")
                    self._send(401, _HTML_UNAUTHORIZED)
                    return

            incoming_ip = (
                self.headers.get("Cf-Connecting-Ip")
                or (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
                or self.client_address[0]
            )
            print(f"[trigger] Request from {incoming_ip}")

            updated_labels = []
            any_error      = False

            for cfg in rule_configs:
                with cfg.lock:
                    # Bootstrap cached IP if unknown
                    if cfg.cached_ip is None:
                        now = time.time()
                        cooldown_ok = (
                            cfg.rule_fetch_failed_at is None
                            or now - cfg.rule_fetch_failed_at >= _RULE_FETCH_COOLDOWN
                        )
                        if cooldown_ok:
                            try:
                                cfg.cached_ip = cfg.fetch_rule_value()
                            except Exception as e:
                                print(f"[{cfg.label}][error] Could not fetch rule value: {e}")
                            if cfg.cached_ip is None:
                                cfg.rule_fetch_failed_at = now

                    if cfg.cached_ip is None:
                        any_error = True
                        continue

                    if incoming_ip != cfg.cached_ip:
                        try:
                            cfg.push_rule(incoming_ip)
                            cfg.cached_ip = incoming_ip
                            updated_labels.append(cfg.label)
                        except Exception as e:
                            print(f"[{cfg.label}][error] {e}")
                            any_error = True
                    else:
                        print(f"[{cfg.label}][trigger] IP unchanged ({incoming_ip})")

            if any_error and not updated_labels:
                self._send(500, _HTML_NOK)
            elif not updated_labels:
                self._send(200, _HTML_NO_CHANGE)
            else:
                self._send(200, _HTML_OK.format(
                    ip=incoming_ip,
                    rules=", ".join(updated_labels),
                ))

        def _send(self, code: int, body: str) -> None:
            encoded = body.encode()
            self.send_response(code)
            self.send_header("Content-Type",   "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def log_message(self, format, *args):
            pass  # suppress default CLF access log

    return TriggerHandler


def run_trigger_server(rule_configs: list[RuleConfig]) -> None:
    handler = make_trigger_handler(rule_configs)
    print(
        f"[info] Trigger server on :{TRIGGER_WEBSITE_PORT} "
        f"({TRIGGER_WEBSITE_DOMAIN}{TRIGGER_WEBSITE_PATH})"
        f" — watching {len(rule_configs)} rule(s)"
    )
    with HTTPServer(("0.0.0.0", TRIGGER_WEBSITE_PORT), handler) as httpd:
        httpd.serve_forever()


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    rule_configs = load_rule_configs()
    print(f"[info] Loaded {len(rule_configs)} rule configuration(s): "
          f"{[c.label for c in rule_configs]}")

    # Bootstrap: fetch current value from Pangolin for each rule
    for cfg in rule_configs:
        print(f"[{cfg.label}][info] Fetching initial rule state from Pangolin...")
        cfg.cached_ip = cfg.fetch_rule_value()
        if cfg.cached_ip:
            print(f"[{cfg.label}][info] Cached IP: {cfg.cached_ip}")
        else:
            print(f"[{cfg.label}][warn] Could not fetch initial rule value; will push on first check")

    if EXPOSE_TRIGGER_WEBSITE:
        # Trigger mode: no background threads needed — single-threaded HTTP server
        run_trigger_server(rule_configs)
    else:
        # Polling mode: one thread per rule (first rule runs on main thread)
        threads = []
        for cfg in rule_configs[1:]:
            t = threading.Thread(target=run_polling_loop, args=(cfg,), name=cfg.label, daemon=True)
            t.start()
            threads.append(t)

        run_polling_loop(rule_configs[0])  # blocks forever on main thread


if __name__ == "__main__":
    main()
