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

Every RULE_N_ block inherits global optional defaults but can override each
one individually. All variables support both global and per-rule forms:

    Global (fallback)            Per-rule override
    ───────────────────────────  ──────────────────────────────────
    PANGOLIN_HOST                RULE_N_PANGOLIN_HOST
    LOOP_SECONDS                 RULE_N_LOOP_SECONDS
    LOOP_JITTER                  RULE_N_LOOP_JITTER
    RULE_PRIORITY                RULE_N_RULE_PRIORITY
    RULE_ACTION                  RULE_N_RULE_ACTION
    RULE_MATCH                   RULE_N_RULE_MATCH
    RULE_ENABLED                 RULE_N_RULE_ENABLED
    TARGET_DOMAIN                RULE_N_TARGET_DOMAIN
    IP_SERVICE_URL               RULE_N_IP_SERVICE_URL
    EXPOSE_TRIGGER_WEBSITE       RULE_N_EXPOSE_TRIGGER_WEBSITE
    TRIGGER_WEBSITE_DOMAIN       RULE_N_TRIGGER_WEBSITE_DOMAIN
    TRIGGER_WEBSITE_PATH         RULE_N_TRIGGER_WEBSITE_PATH
    TRIGGER_WEBSITE_PORT         RULE_N_TRIGGER_WEBSITE_PORT
    TRIGGER_SECRET               RULE_N_TRIGGER_SECRET

Each rule independently chooses its mode:
  • EXPOSE_TRIGGER_WEBSITE=False (default) → polling loop
  • EXPOSE_TRIGGER_WEBSITE=True            → HTTP trigger server on its own port

Rules in trigger mode each bind their own port (TRIGGER_WEBSITE_PORT must be
unique per rule). Rules in polling mode run in parallel threads alongside any
trigger servers.
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

# ── Global / shared optional defaults ─────────────────────────────────────────

# Fallback used when neither RULE_N_IP_SERVICE_URL nor IP_SERVICE_URL is set.
_DEFAULT_IP_SERVICES = "https://wtfismyip.com/text,https://api.ipify.org,https://icanhazip.com"

_RULE_FETCH_COOLDOWN = 60   # seconds before retrying a failed Pangolin fetch


# ── Per-rule configuration ─────────────────────────────────────────────────────

@dataclass
class RuleConfig:
    # Identity
    label: str                       # e.g. "rule-1" or "legacy"

    # Required
    api_key: str
    resource_id: str
    rule_id: str
    pangolin_host: str

    # Rule behaviour
    target_domain: Optional[str]     # resolve this hostname instead of own IP
    loop_seconds: int
    loop_jitter: int
    rule_priority: int
    rule_action: str
    rule_match: str
    rule_enabled: bool
    ip_service_urls: list

    # Trigger-website settings (per-rule)
    expose_trigger_website: bool
    trigger_domain: str
    trigger_path: str
    trigger_port: int
    trigger_secret: str

    # Internals — created automatically
    session: requests.Session = field(default_factory=requests.Session)
    cached_ip: Optional[str] = None
    ip_service_index: int = 0
    rule_fetch_failed_at: Optional[float] = None
    lock: threading.Lock = field(default_factory=threading.Lock)

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

def _pick(prefix: str, key: str, default: str) -> str:
    """Return RULE_N_KEY if set, else KEY if set, else default."""
    if prefix:
        v = os.environ.get(f"{prefix}{key}")
        if v is not None:
            return v
    return os.environ.get(key, default)


def _build_rule(label: str, prefix: str) -> RuleConfig:
    """Build a RuleConfig from env vars, using prefix for per-rule overrides."""
    ip_svc_raw = _pick(prefix, "IP_SERVICE_URL", _DEFAULT_IP_SERVICES)
    ip_services = [u.strip() for u in ip_svc_raw.split(",") if u.strip()]

    return RuleConfig(
        label         = label,
        api_key       = _pick(prefix, "API_KEY",       ""),
        resource_id   = _pick(prefix, "RESOURCE_ID",   ""),
        rule_id       = _pick(prefix, "RULE_ID",        ""),
        pangolin_host = _pick(prefix, "PANGOLIN_HOST",  "https://api.pangolin.example"),
        target_domain = (_pick(prefix, "TARGET_DOMAIN", "").strip() or None),
        loop_seconds  = int(_pick(prefix, "LOOP_SECONDS",   "60")),
        loop_jitter   = int(_pick(prefix, "LOOP_JITTER",    "10")),
        rule_priority = int(_pick(prefix, "RULE_PRIORITY",  "100")),
        rule_action   = _pick(prefix, "RULE_ACTION",  "ACCEPT").upper(),
        rule_match    = _pick(prefix, "RULE_MATCH",   "IP").upper(),
        rule_enabled  = _pick(prefix, "RULE_ENABLED", "True").lower() == "true",
        ip_service_urls = ip_services,
        expose_trigger_website = _pick(prefix, "EXPOSE_TRIGGER_WEBSITE", "False").lower() == "true",
        trigger_domain = _pick(prefix, "TRIGGER_WEBSITE_DOMAIN", "trigger.my.dyn.dns.com"),
        trigger_path   = _pick(prefix, "TRIGGER_WEBSITE_PATH",   "/update"),
        trigger_port   = int(_pick(prefix, "TRIGGER_WEBSITE_PORT", "8080")),
        trigger_secret = _pick(prefix, "TRIGGER_SECRET", ""),
    )


def load_rule_configs() -> list[RuleConfig]:
    configs: list[RuleConfig] = []

    # ── Discover numbered blocks: RULE_1_, RULE_2_, … ─────────────────────────
    # A block is recognised if it sets ANY of the three required keys.
    # The others may come from global fallbacks (e.g. a shared API_KEY).
    numbered: dict[int, str] = {}
    _TRIGGER_KEYS = {"_API_KEY", "_RESOURCE_ID", "_RULE_ID"}
    for key in os.environ:
        if key.startswith("RULE_"):
            for suffix in _TRIGGER_KEYS:
                if key.endswith(suffix):
                    middle = key[len("RULE_"):-len(suffix)]
                    if middle.isdigit():
                        numbered[int(middle)] = f"RULE_{middle}_"
                    break

    if numbered:
        for idx in sorted(numbered):
            prefix = numbered[idx]
            label  = f"rule-{idx}"
            cfg = _build_rule(label, prefix)
            if not all([cfg.api_key, cfg.resource_id, cfg.rule_id]):
                print(f"[warn] Skipping {label}: missing API_KEY / RESOURCE_ID / RULE_ID")
                continue
            configs.append(cfg)
        return configs

    # ── Legacy single-rule (original env var names, no prefix) ────────────────
    cfg = _build_rule("legacy", "")
    if not all([cfg.api_key, cfg.resource_id, cfg.rule_id]):
        raise EnvironmentError(
            "No rule configuration found. "
            "Set API_KEY / RESOURCE_ID / RULE_ID for a single rule, "
            "or RULE_1_API_KEY / RULE_1_RESOURCE_ID / RULE_1_RULE_ID etc. for multiple rules."
        )
    configs.append(cfg)
    return configs


# ── Polling loop ───────────────────────────────────────────────────────────────

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


# ── Trigger website (per-rule) ─────────────────────────────────────────────────

_HTML_OK = """<html><head><title>IP Update Trigger</title></head><body>
<h1>IP Update Trigger</h1><p>Update triggered successfully.</p>
<p>New IP: {ip}</p></body></html>"""

_HTML_NOK = """<html><head><title>IP Update Trigger</title></head><body>
<h1>IP Update Trigger</h1><p>Update could not be triggered.</p></body></html>"""

_HTML_NO_CHANGE = """<html><head><title>IP Update Trigger</title></head><body>
<h1>IP Update Trigger</h1><p>No change — IP is already up-to-date.</p></body></html>"""

_HTML_UNAUTHORIZED = """<html><head><title>IP Update Trigger</title></head><body>
<h1>IP Update Trigger</h1><p>Unauthorized.</p></body></html>"""


def make_trigger_handler(cfg: RuleConfig):
    """Return an HTTP handler class bound to a single RuleConfig."""

    class TriggerHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)
            host   = self.headers.get("Host", "").split(":")[0]
            path   = parsed.path

            if path != cfg.trigger_path or host != cfg.trigger_domain:
                self._send(404, "<h1>Not Found</h1>")
                return

            if cfg.trigger_secret:
                provided = parse_qs(parsed.query).get("token", [""])[0]
                if provided != cfg.trigger_secret:
                    print(f"[{cfg.label}][warn] Unauthorized trigger attempt — bad or missing token")
                    self._send(401, _HTML_UNAUTHORIZED)
                    return

            incoming_ip = (
                self.headers.get("Cf-Connecting-Ip")
                or (self.headers.get("X-Forwarded-For") or "").split(",")[0].strip()
                or self.client_address[0]
            )
            print(f"[{cfg.label}][trigger] Request from {incoming_ip}")

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
                    self._send(503, _HTML_NOK)
                    return

                if incoming_ip != cfg.cached_ip:
                    try:
                        cfg.push_rule(incoming_ip)
                        cfg.cached_ip = incoming_ip
                        self._send(200, _HTML_OK.format(ip=incoming_ip))
                    except Exception as e:
                        print(f"[{cfg.label}][error] {e}")
                        self._send(500, _HTML_NOK)
                else:
                    print(f"[{cfg.label}][trigger] IP unchanged ({incoming_ip})")
                    self._send(200, _HTML_NO_CHANGE)

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


def run_trigger_server(cfg: RuleConfig) -> None:
    handler = make_trigger_handler(cfg)
    print(
        f"[{cfg.label}][info] Trigger server on :{cfg.trigger_port} "
        f"({cfg.trigger_domain}{cfg.trigger_path})"
    )
    with HTTPServer(("0.0.0.0", cfg.trigger_port), handler) as httpd:
        httpd.serve_forever()


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    rule_configs = load_rule_configs()

    # Summarise modes at startup
    for cfg in rule_configs:
        mode = (
            f"trigger :{cfg.trigger_port}{cfg.trigger_path}"
            if cfg.expose_trigger_website
            else f"polling every ~{cfg.loop_seconds}s"
        )
        print(f"[info] {cfg.label}: {mode}")

    # Validate: trigger-mode rules must each have a unique port
    trigger_ports: dict[int, str] = {}
    for cfg in rule_configs:
        if cfg.expose_trigger_website:
            if cfg.trigger_port in trigger_ports:
                raise ValueError(
                    f"[{cfg.label}] TRIGGER_WEBSITE_PORT {cfg.trigger_port} is already used by "
                    f"{trigger_ports[cfg.trigger_port]}. Each trigger rule needs a unique port."
                )
            trigger_ports[cfg.trigger_port] = cfg.label

    # Bootstrap: fetch current rule value from Pangolin for every rule
    for cfg in rule_configs:
        print(f"[{cfg.label}][info] Fetching initial rule state from Pangolin...")
        cfg.cached_ip = cfg.fetch_rule_value()
        if cfg.cached_ip:
            print(f"[{cfg.label}][info] Cached IP: {cfg.cached_ip}")
        else:
            print(f"[{cfg.label}][warn] Could not fetch initial rule value; will push on first check")

    threads: list[threading.Thread] = []

    # Start all rules except the last one in background threads
    for cfg in rule_configs[:-1]:
        if cfg.expose_trigger_website:
            target = run_trigger_server
        else:
            target = run_polling_loop
        t = threading.Thread(target=target, args=(cfg,), name=cfg.label, daemon=True)
        t.start()
        threads.append(t)

    # Run the last rule on the main thread (keeps the process alive)
    last = rule_configs[-1]
    if last.expose_trigger_website:
        run_trigger_server(last)
    else:
        run_polling_loop(last)


if __name__ == "__main__":
    main()
