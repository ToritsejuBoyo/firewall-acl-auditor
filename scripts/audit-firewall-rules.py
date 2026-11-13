#!/usr/bin/env python3
"""Multi-Vendor Firewall & ACL Conflict Auditor (audit-firewall-rules.py)

Deterministic multi-vendor firewall and ACL conflict auditor.
Normalizes rule configurations from Cisco ASA / IOS, Fortinet FortiGate, and
MikroTik RouterOS into a canonical packet-space schema, audits for shadowed
and redundant rules, overly permissive permissions, and insecure protocol
exposure using pure bitwise subnet math.

Generates vendor-accurate CLI cleanup commands and safe rollback scripts.
Zero external dependencies - Python standard library only.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import functools
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Shared residual sanitization pass (vendored: scripts/sanitizer.py).
# Runs last, after this skill's domain-specific masking, so that every skill in
# the library enforces an identical credential/PII floor. See
# tests/sanitizer_conformance_test.py for the contract this must satisfy.
# ---------------------------------------------------------------------------
try:
    from sanitizer import residual_scrub as _residual_scrub
except ImportError:  # pragma: no cover - direct execution from another cwd
    import os as _os
    import sys as _sys
    _sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
    from sanitizer import residual_scrub as _residual_scrub


HIGH_RISK_PORTS: Dict[int, str] = {
    21: "FTP (Plaintext file transfer)",
    22: "SSH (Unrestricted remote shell)",
    23: "Telnet (Unencrypted remote CLI)",
    161: "SNMP (Network management probe)",
    445: "SMB (Direct host file sharing / lateral movement risk)",
    1433: "MSSQL (Database port)",
    3306: "MySQL (Database port)",
    3389: "RDP (Exposed remote desktop service)",
    5432: "PostgreSQL (Database port)",
    8291: "MikroTik-WinBox (Remote GUI management)",
    8728: "MikroTik-API (Remote management API)",
}

WELL_KNOWN_PORT_NAMES: Dict[str, int] = {
    "http": 80,
    "www": 80,
    "https": 443,
    "ssl": 443,
    "ssh": 22,
    "telnet": 23,
    "smtp": 25,
    "dns": 53,
    "domain": 53,
    "dhcps": 67,
    "dhcpc": 68,
    "tftp": 69,
    "finger": 79,
    "pop3": 110,
    "ntp": 123,
    "snmp": 161,
    "snmptrap": 162,
    "bgp": 179,
    "ldap": 389,
    "ldaps": 636,
    "smb": 445,
    "microsoft-ds": 445,
    "imap": 143,
    "imaps": 993,
    "rdp": 3389,
    "sip": 5060,
}


@dataclass
class NormalizedRule:
  vendor: str
  chain_or_acl: str
  seq_or_id: str
  action: str  # "permit" or "deny"
  protocol: str  # "ip", "tcp", "udp", "icmp"
  src_cidr: str
  dst_cidr: str
  dst_port: str  # "any" or port number/range e.g. "443", "80-85"
  enabled: bool
  raw_line: str
  comment: str = ""
  conn_state: str = ""

  def to_dict(self) -> Dict[str, Any]:
    return asdict(self)


@dataclass
class Finding:
  finding_id: str
  severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
  category: (
      str  # SHADOWED_CONFLICT, REDUNDANT_DUPLICATE, PERMISSIVE_ANY_ANY,
           # WAN_EXPOSED_MANAGEMENT_PORT, MISSING_EXPLICIT_DROP_MIKROTIK,
           # DISABLED_RULE
  )
  chain: str
  rule_id: str
  conflicting_rule_id: Optional[str]
  description: str
  remediation_cli: List[str] = field(default_factory=list)
  rollback_cli: List[str] = field(default_factory=list)

  def to_dict(self) -> Dict[str, Any]:
    return asdict(self)


class Sanitizer:
  """Deterministic data sanitizer for network telemetry.

  Replaces IP addresses with RFC 5737 test prefixes and scrubs secrets.
  """

  def __init__(self):
    self.ip_mapping: Dict[str, str] = {}
    self.counter = 1

  def sanitize_ip_or_cidr(self, net_str: str) -> str:
    s = net_str.strip()
    if s in ("0.0.0.0/0", "any", "any4", "all", ""):
      return "0.0.0.0/0"
    if s in self.ip_mapping:
      return self.ip_mapping[s]

    try:
      net = ipaddress.ip_network(s, strict=False)
      idx = self.counter % 250
      self.counter += 1
      if net.num_addresses == 1:
        mock = f"198.51.100.{idx}/32"
      else:
        plen = net.prefixlen
        mock = f"192.0.2.{(idx // 16) * 16}/{plen if plen >= 24 else 24}"
      self.ip_mapping[s] = mock
      return mock
    except Exception:
      mock = f"192.0.2.{self.counter}/32"
      self.counter += 1
      self.ip_mapping[s] = mock
      return mock

  def scrub_secrets(self, text: str) -> str:
    scrubbed = re.sub(
        r"(pre-shared-key|password|secret|community)\s+[^\s\n\r]+",
        r"\1 [REDACTED-SECRET]",
        text,
        flags=re.IGNORECASE,
    )
    scrubbed = re.sub(
        r"set\s+(preshared-key|password)\s+\"[^\"]+\"",
        r'set \1 "[REDACTED-SECRET]"',
        scrubbed,
        flags=re.IGNORECASE,
    )
    scrubbed = _residual_scrub(scrubbed, skip=frozenset({'ipv4', 'ipv6'}))
    return scrubbed

  def sanitize_raw_line(self, line: str) -> str:
    # Scrub secrets first
    clean = self.scrub_secrets(line)
    # Mask any IPv4 addresses in the line
    def _sub_ip(match):
      ip = match.group(0)
      if ip == "0.0.0.0" or ip == "255.255.255.255":
        return ip
      return self.sanitize_ip_or_cidr(ip).split("/")[0]

    clean = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", _sub_ip, clean)
    return clean


@functools.lru_cache(maxsize=4096)
def normalize_network(net_str: Any) -> ipaddress.IPv4Network:
  s = str(net_str).strip().lower()
  if s in ("any", "any4", "all", "0.0.0.0/0", "0.0.0.0 255.255.255.255", ""):
    return ipaddress.IPv4Network("0.0.0.0/0")
  try:
    return ipaddress.IPv4Network(s, strict=False)
  except (ValueError, TypeError):
    return ipaddress.IPv4Network("0.0.0.0/0")


@functools.lru_cache(maxsize=8192)
def network_to_int_tuple(net_str: Any) -> Tuple[int, int, int]:
  s = str(net_str).strip().lower()
  if s in ("any", "any4", "all", "0.0.0.0/0", "0.0.0.0 255.255.255.255", ""):
    return (0, 0xFFFFFFFF, 0)
  try:
    net = ipaddress.IPv4Network(s, strict=False)
    return (int(net.network_address), int(net.broadcast_address), net.prefixlen)
  except (ValueError, TypeError):
    return (0, 0xFFFFFFFF, 0)


def is_subnet_fast(sub_tuple: Tuple[int, int, int], super_tuple: Tuple[int, int, int]) -> bool:
  return (
      super_tuple[2] <= sub_tuple[2]
      and super_tuple[0] <= sub_tuple[0]
      and super_tuple[1] >= sub_tuple[1]
  )


def is_proto_superset(super_proto: str, sub_proto: str) -> bool:
  sp = super_proto.lower()
  subp = sub_proto.lower()
  if sp in ("ip", "all", "any"):
    return True
  return sp == subp


@functools.lru_cache(maxsize=4096)
def parse_port_intervals(p_str: Any) -> Tuple[Tuple[int, int], ...]:
  s = str(p_str).strip().lower()
  if s in ("any", "all", ""):
    return ((0, 65535),)

  intervals: List[Tuple[int, int]] = []
  tokens = [t.strip().strip('"') for t in s.split(",") if t.strip()]
  if not tokens:
    return ((0, 65535),)

  for tok in tokens:
    if tok in WELL_KNOWN_PORT_NAMES:
      val = WELL_KNOWN_PORT_NAMES[tok]
      intervals.append((val, val))
    elif "-" in tok:
      parts = tok.split("-", 1)
      try:
        p1, p2 = int(parts[0]), int(parts[1])
        lo, hi = min(p1, p2), max(p1, p2)
        intervals.append((max(0, min(65535, lo)), max(0, min(65535, hi))))
      except ValueError:
        pass
    else:
      try:
        val = max(0, min(65535, int(tok)))
        intervals.append((val, val))
      except ValueError:
        pass

  if not intervals:
    return ((0, 65535),)

  return tuple(sorted(intervals))


@functools.lru_cache(maxsize=4096)
def parse_port_range(p_str: Any) -> Tuple[int, int]:
  intervals = parse_port_intervals(p_str)
  if not intervals:
    return (0, 65535)
  return intervals[0]


def is_port_superset(super_port: str, sub_port: str) -> bool:
  if super_port in ("any", "all", ""):
    return True
  if super_port == sub_port:
    return True

  super_intervals = parse_port_intervals(super_port)
  sub_intervals = parse_port_intervals(sub_port)

  for sub_lo, sub_hi in sub_intervals:
    covered = any(sup_lo <= sub_lo and sup_hi >= sub_hi for sup_lo, sup_hi in super_intervals)
    if not covered:
      return False
  return True


# Maximum number of earlier rules in the same ACL that each rule is compared
# against during shadow analysis. Bounds an inherently quadratic comparison so a
# very large ACL degrades predictably with a reported truncation, rather than
# appearing to hang. Raise it for exhaustive analysis of a huge ACL if you can
# accept the runtime.
SHADOW_SCAN_DEPTH = 2000


def is_rule_superset(r_super: NormalizedRule, r_sub: NormalizedRule) -> bool:
  if r_super.chain_or_acl != r_sub.chain_or_acl:
    return False
  if not is_proto_superset(r_super.protocol, r_sub.protocol):
    return False

  # Connection state: a state-constrained rule (e.g. established,related) cannot shadow an unconstrained rule
  if r_super.conn_state and not r_sub.conn_state:
    return False
  if r_super.conn_state and r_sub.conn_state and r_super.conn_state != r_sub.conn_state:
    return False

  # Fast-path for source CIDR
  if r_super.src_cidr != "0.0.0.0/0" and r_super.src_cidr != r_sub.src_cidr:
    if not is_subnet_fast(network_to_int_tuple(r_sub.src_cidr), network_to_int_tuple(r_super.src_cidr)):
      return False

  # Fast-path for destination CIDR
  if r_super.dst_cidr != "0.0.0.0/0" and r_super.dst_cidr != r_sub.dst_cidr:
    if not is_subnet_fast(network_to_int_tuple(r_sub.dst_cidr), network_to_int_tuple(r_super.dst_cidr)):
      return False

  if not is_port_superset(r_super.dst_port, r_sub.dst_port):
    return False
  return True


def detect_vendor(text: str) -> str:
  content_lower = text.lower()
  if text.strip().startswith("[") and (
      "rule_id" in content_lower or "src_cidr" in content_lower
  ):
    return "json"
  if (
      "/ip firewall filter" in content_lower
      or "chain=forward" in content_lower
      or "chain=input" in content_lower
  ):
    return "mikrotik"
  if "config firewall policy" in content_lower or "set srcintf" in content_lower:
    return "fortigate"
  return "cisco"


def parse_cisco(text: str) -> List[NormalizedRule]:
  rules: List[NormalizedRule] = []
  current_acl = "GLOBAL-ACL"
  seq_counter = 10

  for line in text.splitlines():
    raw = line.strip()
    if not raw or raw.startswith("!") or raw.startswith("remark"):
      continue

    m_named = re.match(
        r"^ip access-list (?:extended|standard)\s+(\S+)", raw, re.IGNORECASE
    )
    if m_named:
      current_acl = m_named.group(1)
      seq_counter = 10
      continue

    work = raw
    acl_name = current_acl
    seq = str(seq_counter)

    m_asa = re.match(r"^access-list\s+(\S+)\s+(.*)$", work, re.IGNORECASE)
    if m_asa:
      acl_name = m_asa.group(1)
      work = m_asa.group(2)
      m_line = re.search(r"\bline\s+(\d+)\b", work, re.IGNORECASE)
      if m_line:
        seq = m_line.group(1)
        work = re.sub(r"\bline\s+\d+\b", "", work, flags=re.IGNORECASE).strip()
      work = re.sub(r"\bextended\b", "", work, flags=re.IGNORECASE).strip()
    else:
      m_seq = re.match(r"^(\d+)\s+(.*)$", work)
      if m_seq:
        seq = m_seq.group(1)
        work = m_seq.group(2)

    is_disabled = bool(re.search(r"\binactive\b", work, re.IGNORECASE))
    work = re.sub(r"\binactive\b", "", work, flags=re.IGNORECASE).strip()

    m_act = re.match(r"^(permit|deny)\s+(\S+)\s+(.*)$", work, re.IGNORECASE)
    if not m_act:
      continue

    action = m_act.group(1).lower()
    proto = m_act.group(2).lower()
    rest = m_act.group(3).strip()
    rest = re.sub(r"\s*\(hitcnt=\d+\).*$", "", rest)
    rest = re.sub(r"\s+log(?:-input)?\s*$", "", rest, flags=re.IGNORECASE)

    tokens = rest.split()
    idx = 0

    def consume_addr(toks: List[str], pos: int) -> Tuple[str, int]:
      if pos >= len(toks):
        return ("0.0.0.0/0", pos)
      t = toks[pos].lower()
      if t in ("any", "any4"):
        return ("0.0.0.0/0", pos + 1)
      if t == "host" and pos + 1 < len(toks):
        return (f"{toks[pos+1]}/32", pos + 2)
      if pos + 1 < len(toks) and re.match(r"^\d+\.\d+\.\d+\.\d+$", toks[pos + 1]):
        ip_part = toks[pos]
        mask_part = toks[pos + 1]
        octets = [int(x) for x in mask_part.split(".")]
        if octets[0] == 0 and any(o > 0 for o in octets):
          inv = ".".join(str(255 - o) for o in octets)
          return (str(normalize_network(f"{ip_part}/{inv}")), pos + 2)
        return (str(normalize_network(f"{ip_part}/{mask_part}")), pos + 2)
      return (t, pos + 1)

    src_cidr, idx = consume_addr(tokens, idx)
    dst_cidr, idx = consume_addr(tokens, idx)
    dst_port = "any"
    if idx < len(tokens):
      if tokens[idx].lower() == "eq" and idx + 1 < len(tokens):
        p = tokens[idx + 1].lower()
        dst_port = str(WELL_KNOWN_PORT_NAMES.get(p, p))
      elif tokens[idx].lower() == "range" and idx + 2 < len(tokens):
        dst_port = f"{tokens[idx+1]}-{tokens[idx+2]}"

    rules.append(
        NormalizedRule(
            vendor="cisco",
            chain_or_acl=acl_name,
            seq_or_id=seq,
            action=action,
            protocol=proto,
            src_cidr=src_cidr,
            dst_cidr=dst_cidr,
            dst_port=dst_port,
            enabled=not is_disabled,
            raw_line=raw,
            comment="",
        )
    )
    seq_counter += 10

  return rules


def parse_mikrotik(text: str) -> List[NormalizedRule]:
  rules: List[NormalizedRule] = []
  idx = 0
  for line in text.splitlines():
    raw = line.strip()
    if not raw.startswith("add ") and not raw.startswith(
        "/ip firewall filter add "
    ):
      continue
    idx += 1
    chain_m = re.search(r"chain=(\S+)", raw)
    action_m = re.search(r"action=(\S+)", raw)
    proto_m = re.search(r"protocol=(\S+)", raw)
    src_m = re.search(r"src-address=(\S+)", raw)
    dst_m = re.search(r"dst-address=(\S+)", raw)
    port_m = re.search(r"dst-port=(\S+)", raw)
    conn_m = re.search(r"connection-state=(\S+)", raw)
    dis_m = re.search(r"disabled=(yes|true)", raw, re.IGNORECASE)
    comment_m = re.search(r'comment="?([^"\n]+)"?', raw)

    chain = chain_m.group(1) if chain_m else "forward"
    raw_action = (action_m.group(1) if action_m else "accept").lower()
    action = "deny" if raw_action in ("drop", "reject") else "permit"
    proto = proto_m.group(1).lower() if proto_m else "ip"
    src = src_m.group(1) if src_m else "0.0.0.0/0"
    dst = dst_m.group(1) if dst_m else "0.0.0.0/0"
    port = port_m.group(1) if port_m else "any"
    comment = comment_m.group(1) if comment_m else f"rule-{idx}"
    conn_state = conn_m.group(1).lower() if conn_m else ""

    rules.append(
        NormalizedRule(
            vendor="mikrotik",
            chain_or_acl=chain,
            seq_or_id=str(idx),
            action=action,
            protocol=proto,
            src_cidr=str(normalize_network(src)),
            dst_cidr=str(normalize_network(dst)),
            dst_port=port,
            enabled=not bool(dis_m),
            raw_line=raw,
            comment=comment,
            conn_state=conn_state,
        )
    )
  return rules


def parse_fortigate(text: str) -> List[NormalizedRule]:
  rules: List[NormalizedRule] = []
  blocks = re.split(r"\bedit\s+(\d+)\b", text)
  for i in range(1, len(blocks) - 1, 2):
    pol_id = blocks[i].strip()
    body = blocks[i + 1]
    name_m = re.search(r'set name\s+"?([^"\n]+)"?', body)
    srcintf = re.search(r'set srcintf\s+"?([^"\n]+)"?', body)
    dstintf = re.search(r'set dstintf\s+"?([^"\n]+)"?', body)
    srcaddr = re.search(r'set srcaddr\s+"?([^"\n]+)"?', body)
    dstaddr = re.search(r'set dstaddr\s+"?([^"\n]+)"?', body)
    action_m = re.search(r"set action\s+(\S+)", body)
    service_m = re.search(r'set service\s+(.*)', body)
    status_m = re.search(r"set status\s+(disable)", body)

    s_int = srcintf.group(1).strip() if srcintf else "any"
    d_int = dstintf.group(1).strip() if dstintf else "any"
    chain = f"{s_int}->{d_int}"
    act = (
        "permit"
        if (action_m and action_m.group(1).lower() == "accept")
        else "deny"
    )
    s_addr = srcaddr.group(1).strip() if srcaddr else "all"
    d_addr = dstaddr.group(1).strip() if dstaddr else "all"

    services: List[str] = []
    if service_m:
      raw_svc = service_m.group(1).strip().split("\n")[0]
      tokens = re.findall(r'"([^"]+)"|(\S+)', raw_svc)
      for m1, m2 in tokens:
        w = (m1 or m2).strip().lower()
        if w:
          services.append(w)
    if not services:
      services = ["all"]

    proto = "ip"
    ports: List[str] = []
    for s in services:
      if s in WELL_KNOWN_PORT_NAMES:
        ports.append(str(WELL_KNOWN_PORT_NAMES[s]))
        proto = "tcp"
      elif s == "all":
        ports.append("any")

    port = ",".join(ports) if ports else "any"
    if "any" in ports:
      port = "any"

    comment = name_m.group(1) if name_m else f"policy-{pol_id}"

    src_cidr = "0.0.0.0/0" if s_addr.lower() == "all" else s_addr
    dst_cidr = "0.0.0.0/0" if d_addr.lower() == "all" else d_addr

    rules.append(
        NormalizedRule(
            vendor="fortigate",
            chain_or_acl=chain,
            seq_or_id=pol_id,
            action=act,
            protocol=proto,
            src_cidr=str(normalize_network(src_cidr)),
            dst_cidr=str(normalize_network(dst_cidr)),
            dst_port=port,
            enabled=not bool(status_m),
            raw_line=(
                f"edit {pol_id} ({chain}: {s_addr} -> {d_addr} service"
                f" {' '.join(services)} action {act})"
            ),
            comment=comment,
        )
    )
  return rules


def parse_normalized_json(text: str) -> List[NormalizedRule]:
  data = json.loads(text)
  if isinstance(data, dict):
    if "rules" in data and isinstance(data["rules"], list):
      data = data["rules"]
    elif "value" in data and isinstance(data["value"], list):
      data = data["value"]
    else:
      data = [data]
  elif not isinstance(data, list):
    raise ValueError("JSON input must be a list of rule objects or dict containing 'rules'")

  rules: List[NormalizedRule] = []
  for idx, item in enumerate(data, start=1):
    if not isinstance(item, dict):
      continue
    src_prefixes = item.get(
        "src_prefixes", [item.get("src_cidr", "0.0.0.0/0")]
    )
    if not src_prefixes:
      src_prefixes = ["0.0.0.0/0"]
    dst_prefixes = item.get(
        "dst_prefixes", [item.get("dst_cidr", "0.0.0.0/0")]
    )
    if not dst_prefixes:
      dst_prefixes = ["0.0.0.0/0"]
    dst_ports = item.get("dst_ports", [item.get("dst_port", "any")])
    if not dst_ports:
      dst_ports = ["any"]
    status = str(item.get("status", "enabled")).lower()

    rules.append(
        NormalizedRule(
            vendor=str(item.get("vendor", "generic")),
            chain_or_acl=str(item.get(
                "policy_group", item.get("chain_or_acl", "GLOBAL")
            )),
            seq_or_id=str(item.get("rule_id", item.get("seq_or_id", str(idx)))),
            action=str(item.get("action", "permit")).lower(),
            protocol=str(item.get("protocol", "ip")).lower(),
            src_cidr=str(normalize_network(src_prefixes[0])),
            dst_cidr=str(normalize_network(dst_prefixes[0])),
            dst_port=str(dst_ports[0]),
            enabled=(status != "disabled"),
            raw_line=str(item.get("raw_text", item.get("raw_line", f"Rule-{idx}"))),
            comment=str(item.get("comment", "")),
        )
    )
  return rules


# ---------------------------------------------------------
# Remediation & Rollback Script Generators
# ---------------------------------------------------------


def generate_remediation_cli(
    category: str,
    r_sub: NormalizedRule,
    r_super: Optional[NormalizedRule],
    vendor: str,
) -> Tuple[List[str], List[str]]:
  rem_cli: List[str] = []
  roll_cli: List[str] = []

  if vendor == "cisco":
    if category == "SHADOWED_CONFLICT" and r_super:
      rem_cli.append(
          f"! Move Rule {r_sub.seq_or_id} ahead of line {r_super.seq_or_id}"
      )
      rem_cli.append(
          f"ip access-list extended {r_sub.chain_or_acl} resequence 10 10"
      )
      rem_cli.append(
          f"! Insert exception before line {r_super.seq_or_id} in"
          f" {r_sub.chain_or_acl}"
      )
      rem_cli.append(f"no {r_sub.raw_line}")
      roll_cli.append(
          f"! Restore previous order of Rule {r_sub.seq_or_id} on"
          f" {r_sub.chain_or_acl}"
      )
      roll_cli.append(f"{r_sub.raw_line}")
    elif category == "REDUNDANT_DUPLICATE":
      rem_cli.append(f"no {r_sub.raw_line}")
      roll_cli.append(f"{r_sub.raw_line}")
    elif category == "PERMISSIVE_ANY_ANY":
      rem_cli.append(f"no {r_sub.raw_line}")
      rem_cli.append(
          f"! Replace with restrictive subnet rules on {r_sub.chain_or_acl}"
      )
      roll_cli.append(f"{r_sub.raw_line}")

  elif vendor == "fortigate":
    if category == "SHADOWED_CONFLICT" and r_super:
      rem_cli.append("config firewall policy")
      rem_cli.append(
          f"    move {r_sub.seq_or_id} before {r_super.seq_or_id}"
      )
      rem_cli.append("end")
      roll_cli.append("config firewall policy")
      roll_cli.append(
          f"    move {r_sub.seq_or_id} after {r_super.seq_or_id}"
      )
      roll_cli.append("end")
    elif category == "REDUNDANT_DUPLICATE":
      rem_cli.append("config firewall policy")
      rem_cli.append(f"    delete {r_sub.seq_or_id}")
      rem_cli.append("end")
      roll_cli.append(
          f"! Re-create policy {r_sub.seq_or_id} if emergency roll-back"
          " required"
      )
    elif category == "PERMISSIVE_ANY_ANY":
      rem_cli.append("config firewall policy")
      rem_cli.append(f"    delete {r_sub.seq_or_id}")
      rem_cli.append("end")
      roll_cli.append(
          f"! Restore policy {r_sub.seq_or_id} if emergency roll-back required"
      )

  elif vendor == "mikrotik":
    cmt = (
        r_sub.comment
        if r_sub.comment
        else f"rule-{r_sub.seq_or_id}"
    )
    sup_cmt = (
        r_super.comment
        if (r_super and r_super.comment)
        else (f"rule-{r_super.seq_or_id}" if r_super else "")
    )
    if category == "SHADOWED_CONFLICT" and r_super:
      rem_cli.append(
          f'/ip firewall filter move [find comment="{cmt}"] [find'
          f' comment="{sup_cmt}"]'
      )
      roll_cli.append(
          f'/ip firewall filter move [find comment="{cmt}"]'
          f" {int(r_sub.seq_or_id) - 1}"
      )
    elif category == "REDUNDANT_DUPLICATE":
      rem_cli.append(f'/ip firewall filter remove [find comment="{cmt}"]')
      roll_cli.append(f"{r_sub.raw_line}")
    elif category == "PERMISSIVE_ANY_ANY":
      rem_cli.append(f'/ip firewall filter remove [find comment="{cmt}"]')
      roll_cli.append(f"{r_sub.raw_line}")
    elif category == "MISSING_EXPLICIT_DROP_MIKROTIK":
      rem_cli.append(
          f'/ip firewall filter add chain={r_sub.chain_or_acl} action=drop'
          ' comment="FINAL-DEFAULT-DROP"'
      )
      roll_cli.append(
          '/ip firewall filter remove [find comment="FINAL-DEFAULT-DROP"]'
      )

  else:  # Generic
    if category in ("SHADOWED_CONFLICT", "REDUNDANT_DUPLICATE"):
      rem_cli.append(
          f"PRUNE_OR_REORDER_RULE: {r_sub.seq_or_id} (Preceded by"
          f" {r_super.seq_or_id if r_super else 'N/A'})"
      )
      roll_cli.append(f"RESTORE_RULE: {r_sub.seq_or_id}")

  return rem_cli, roll_cli


# ---------------------------------------------------------
# Audit Engine
# ---------------------------------------------------------


def audit_rules(
    rules: List[NormalizedRule],
    sanitize: bool = False,
    sanitizer: Optional[Sanitizer] = None,
) -> Tuple[List[Finding], Sanitizer]:
  if sanitizer is None:
    sanitizer = Sanitizer()

  findings: List[Finding] = []
  f_idx = 1
  active_rules = [r for r in rules if r.enabled]
  disabled_rules = [r for r in rules if not r.enabled]

  # 0. Audit Disabled / Zombie Rules
  for r in disabled_rules:
    rem, roll = generate_remediation_cli("DISABLED_RULE", r, None, r.vendor)
    findings.append(
        Finding(
            finding_id=f"FINDING-{f_idx:03d}",
            severity="LOW",
            category="DISABLED_RULE",
            chain=r.chain_or_acl,
            rule_id=r.seq_or_id,
            conflicting_rule_id=None,
            description=(
                f"Rule #{r.seq_or_id} is inactive / disabled (Zombie Rule) in"
                f" '{r.chain_or_acl}'. Prune inactive rules to maintain audit"
                " hygiene."
            ),
            remediation_cli=rem,
            rollback_cli=roll,
        )
    )
    f_idx += 1

  # 1. Shadowing & Redundancy Analysis (Pairwise Containment: i < j)
  #
  # Bucketed by chain/ACL first. is_rule_superset() rejects any cross-chain pair
  # outright (a rule in OUTSIDE cannot shadow one in INSIDE - different packet
  # paths), so comparing across chains was pure waste. A naive all-pairs scan is
  # O(n^2) over the whole config; bucketing makes it O(sum(k^2)) over each chain,
  # which on a real multi-ACL firewall is the difference between minutes and
  # seconds. Order within each bucket is preserved, so "earlier rule wins"
  # semantics are unchanged.
  _prior_in_chain: Dict[str, List[NormalizedRule]] = {}
  # Pairwise containment within one ACL is inherently quadratic, and no bucketing
  # changes that for a single very large ACL. Rather than appear to hang - which is
  # the worst possible failure mode for an operator mid-incident - the comparison
  # depth per ACL is bounded and the truncation is reported as a finding, so the
  # limitation is visible in the output instead of being silent.
  #
  # SHADOW_SCAN_DEPTH caps how many earlier rules in the same ACL each rule is
  # compared against. 2000 keeps the worst case to a few seconds while still
  # covering ACLs far larger than production platforms typically permit. Earlier
  # rules take precedence in evaluation order, so the most recent 2000 are the ones
  # most likely to shadow a new rule.
  _truncated_chains = {}
  for j, r_sub in enumerate(active_rules):
    _prior = _prior_in_chain.setdefault(r_sub.chain_or_acl, [])
    _window = _prior
    if len(_prior) > SHADOW_SCAN_DEPTH:
      _window = _prior[-SHADOW_SCAN_DEPTH:]
      _truncated_chains[r_sub.chain_or_acl] = len(_prior)
    for r_super in _window:
      if is_rule_superset(r_super, r_sub):
        if r_super.action != r_sub.action:
          severity = "CRITICAL" if r_super.action == "permit" else "HIGH"
          cat = "SHADOWED_CONFLICT"
          desc = (
              f"Rule #{r_sub.seq_or_id} ({r_sub.action.upper()}) is completely"
              f" shadowed by earlier Rule #{r_super.seq_or_id}"
              f" ({r_super.action.upper()}) in '{r_sub.chain_or_acl}' and will"
              " NEVER match packets."
          )
        else:
          severity = "MEDIUM"
          cat = "REDUNDANT_DUPLICATE"
          desc = (
              f"Rule #{r_sub.seq_or_id} ({r_sub.action.upper()}) is a"
              f" redundant subset of earlier Rule #{r_super.seq_or_id}"
              f" ({r_super.action.upper()}) and can be safely removed."
          )

        rem, roll = generate_remediation_cli(cat, r_sub, r_super, r_sub.vendor)
        findings.append(
            Finding(
                finding_id=f"FINDING-{f_idx:03d}",
                severity=severity,
                category=cat,
                chain=r_sub.chain_or_acl,
                rule_id=r_sub.seq_or_id,
                conflicting_rule_id=r_super.seq_or_id,
                description=desc,
                remediation_cli=rem,
                rollback_cli=roll,
            )
        )
        f_idx += 1
        break

    _prior.append(r_sub)

    # 2. Overly Permissive ANY-ANY Permit
    if (
        r_sub.action == "permit"
        and r_sub.src_cidr == "0.0.0.0/0"
        and r_sub.dst_cidr == "0.0.0.0/0"
        and r_sub.protocol in ("ip", "all", "any")
        and r_sub.dst_port == "any"
        and not r_sub.conn_state
    ):
      rem, roll = generate_remediation_cli(
          "PERMISSIVE_ANY_ANY", r_sub, None, r_sub.vendor
      )
      findings.append(
          Finding(
              finding_id=f"FINDING-{f_idx:03d}",
              severity="CRITICAL",
              category="PERMISSIVE_ANY_ANY",
              chain=r_sub.chain_or_acl,
              rule_id=r_sub.seq_or_id,
              conflicting_rule_id=None,
              description=(
                  "Unrestricted PERMIT ANY-ANY rule detected at Rule"
                  f" #{r_sub.seq_or_id} in '{r_sub.chain_or_acl}'. Allows all"
                  " traffic across all ports, violating Zero Trust and PCI-DSS"
                  " 1.3."
              ),
              remediation_cli=rem,
              rollback_cli=roll,
          )
      )
      f_idx += 1

    # 3. Exposed High-Risk Management Ports from 0.0.0.0/0
    if (
        r_sub.action == "permit"
        and r_sub.src_cidr == "0.0.0.0/0"
        and r_sub.dst_port != "any"
    ):
      lo, hi = parse_port_range(r_sub.dst_port)
      if hi - lo < 100:
        for port_num, svc_name in HIGH_RISK_PORTS.items():
          if lo <= port_num <= hi:
            findings.append(
                Finding(
                    finding_id=f"FINDING-{f_idx:03d}",
                    severity="HIGH",
                    category="WAN_EXPOSED_MANAGEMENT_PORT",
                    chain=r_sub.chain_or_acl,
                    rule_id=r_sub.seq_or_id,
                    conflicting_rule_id=None,
                    description=(
                        f"Rule #{r_sub.seq_or_id} exposes sensitive service"
                        f" {svc_name} to 0.0.0.0/0 in '{r_sub.chain_or_acl}'."
                    ),
                    remediation_cli=[
                        f"! Restrict source IP on rule {r_sub.seq_or_id} to"
                        " trusted jump-host/bastion"
                    ],
                    rollback_cli=[],
                )
            )
            f_idx += 1

  # 4. MikroTik Implicit Accept Check
  mikrotik_chains = {
      r.chain_or_acl for r in active_rules if r.vendor == "mikrotik"
  }
  for ch in mikrotik_chains:
    chain_rules = [
        r
        for r in active_rules
        if r.vendor == "mikrotik" and r.chain_or_acl == ch
    ]
    if chain_rules:
      last_rule = chain_rules[-1]
      if not (
          last_rule.action == "deny"
          and last_rule.src_cidr == "0.0.0.0/0"
          and last_rule.dst_cidr == "0.0.0.0/0"
      ):
        rem, roll = generate_remediation_cli(
            "MISSING_EXPLICIT_DROP_MIKROTIK", last_rule, None, "mikrotik"
        )
        findings.append(
            Finding(
                finding_id=f"FINDING-{f_idx:03d}",
                severity="CRITICAL",
                category="MISSING_EXPLICIT_DROP_MIKROTIK",
                chain=ch,
                rule_id="END-OF-CHAIN",
                conflicting_rule_id=None,
                description=(
                    f"MikroTik chain '{ch}' does not end with an explicit"
                    " drop-all rule. Unlike Cisco/FortiGate, RouterOS defaults"
                    " to IMPLICIT ACCEPT at the end of every chain!"
                ),
                remediation_cli=rem,
                rollback_cli=roll,
            )
        )
        f_idx += 1

  for _chain, _seen in sorted(_truncated_chains.items()):
    findings.append(
        Finding(
            finding_id=f"FINDING-{f_idx:03d}",
            severity="INFO",
            category="ANALYSIS_TRUNCATED",
            chain=_chain,
            rule_id="-",
            conflicting_rule_id="N/A",
            description=(
                f"ACL '{_chain}' contains {_seen} active rules. Shadow and"
                f" redundancy analysis compared each rule against the"
                f" {SHADOW_SCAN_DEPTH} nearest preceding rules rather than all"
                " of them, to bound an inherently quadratic comparison."
                " Shadowing by a much earlier rule in this ACL may not be"
                " reported. Raise SHADOW_SCAN_DEPTH for exhaustive analysis."
            ),
            remediation_cli="# No action required: analysis coverage note.",
            rollback_cli="# Not applicable.",
        )
    )
    f_idx += 1

  return findings, sanitizer


# ---------------------------------------------------------
# Formatting & Presentation
# ---------------------------------------------------------


def format_markdown(
    rules: List[NormalizedRule],
    findings: List[Finding],
    sanitizer: Sanitizer,
    sanitize: bool,
    vendor: str,
) -> str:
  crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
  high_count = sum(1 for f in findings if f.severity == "HIGH")
  med_count = sum(1 for f in findings if f.severity == "MEDIUM")
  low_count = sum(1 for f in findings if f.severity == "LOW")

  out = []
  out.append(f"# Multi-Vendor Firewall Audit Summary (`{vendor.upper()}`)")
  out.append("")
  out.append("## Executive Summary")
  out.append(f"- **Total Rules Parsed:** `{len(rules)}`")
  out.append(f"- **Total Conflicts & Risks Detected:** `{len(findings)}`")
  out.append(
      f"- **Breakdown:** Critical: {crit_count} | High: {high_count} | Medium:"
      f" {med_count} | Low: {low_count}"
  )
  out.append(
      f"- **Data Sanitization:** {'Active (RFC 5737 Test Prefixes, Secrets Scrubbed)' if sanitize else 'Disabled (Raw Telemetry)'}"
  )
  out.append("")

  if not findings:
    out.append("No shadowed, redundant, or high-risk rules detected.")
    return "\n".join(out)

  out.append("## Prioritized Diagnostic Findings")
  out.append("")
  out.append(
      "| Finding ID | Severity | Category | Chain / ACL | Rule ID | Conflicting"
      " Rule | Description |"
  )
  out.append(
      "| :--- | :--- | :--- | :--- | :--- | :--- |"
      " :----------------------------------------------------------------------------------------------------------------------------------------------------"
      " |"
  )
  for f in findings:
    conf = f.conflicting_rule_id if f.conflicting_rule_id else "N/A"
    desc = f.description
    if sanitize:
      desc = sanitizer.sanitize_raw_line(desc)
    out.append(
        f"| {f.finding_id} | **{f.severity}** | `{f.category}` | `{f.chain}` |"
        f" `{f.rule_id}` | `{conf}` | {desc} |"
    )
  out.append("")

  has_remediation = any(f.remediation_cli for f in findings)
  if has_remediation:
    out.append("## Remediation & Rollback CLI Commands")
    out.append("")
    for f in findings:
      if f.remediation_cli:
        out.append(
            f"### {f.finding_id}: {f.category} on Rule `{f.rule_id}`"
            f" ({f.chain})"
        )
        out.append(f"**Impact:** {f.description}")
        out.append("")
        out.append("```bash")
        out.append("# --- Remediation CLI ---")
        for cmd in f.remediation_cli:
          c = sanitizer.sanitize_raw_line(cmd) if sanitize else cmd
          out.append(c)
        if f.rollback_cli:
          out.append("")
          out.append("# --- Atomic Rollback CLI ---")
          for cmd in f.rollback_cli:
            c = sanitizer.sanitize_raw_line(cmd) if sanitize else cmd
            out.append(c)
        out.append("```")
        out.append("")

  return "\n".join(out)


def _main_impl() -> int:
  parser = argparse.ArgumentParser(
      description=(
          "Deterministic Multi-Vendor Firewall & ACL Conflict Auditor"
          " (Cisco/Fortinet/MikroTik)"
      )
  )
  parser.add_argument(
      "-i",
      "--input",
      required=True,
      help="Path to exported firewall config file.",
  )
  parser.add_argument(
      "-v",
      "--vendor",
      choices=["auto", "cisco", "fortigate", "mikrotik", "json"],
      default="auto",
      help="Firewall vendor syntax (default: auto).",
  )
  parser.add_argument(
      "-f",
      "--format",
      choices=["markdown", "json"],
      default="markdown",
      help="Output format.",
  )
  parser.add_argument(
      "-s",
      "--sanitize",
      action="store_true",
      help=(
          "Mask subnets to RFC 5737 test prefixes and scrub secrets (Rule 4)."
      ),
  )
  parser.add_argument("-o", "--output", help="Optional output file path.")

  args = parser.parse_args()

  try:
    with open(args.input, "r", encoding="utf-8", errors="replace") as f:
      content = f.read()
  except Exception as e:
    sys.stderr.write(f"Error reading input file: {e}\n")
    return 1

  vendor = args.vendor
  if vendor == "auto":
    vendor = detect_vendor(content)

  try:
    if vendor == "mikrotik":
      rules = parse_mikrotik(content)
    elif vendor == "fortigate":
      rules = parse_fortigate(content)
    elif vendor == "json":
      rules = parse_normalized_json(content)
    else:
      rules = parse_cisco(content)
  except Exception as e:
    sys.stderr.write(f"Error parsing {vendor} configuration: {e}\n")
    return 1

  findings, sanitizer = audit_rules(rules, sanitize=args.sanitize)

  if args.format == "json":
    result = {
        "status": "success",
        "vendor": vendor,
        "total_rules": len(rules),
        "total_findings": len(findings),
        "rules": [r.to_dict() for r in rules],
        "findings": [f.to_dict() for f in findings],
    }
    rendered = json.dumps(result, indent=2)
  else:
    rendered = format_markdown(
        rules, findings, sanitizer, args.sanitize, vendor
    )

  if args.output:
    with open(args.output, "w", encoding="utf-8") as f:
      f.write(rendered)
  else:
    print(rendered)

  return 0
def main():
    """
    Hardened entry point.

    Diagnostic input arrives from operators and agents in every broken shape
    there is: an empty export, a directory, a truncated paste, a PDF renamed to
    .json, the wrong encoding. Each must produce one clear diagnostic line and a
    non-zero exit code. A Python traceback is the wrong failure mode here: it is
    unactionable for a technician, and for an agent it leaks absolute filesystem
    paths into a transcript while giving the model nothing it can act on.
    """
    try:
        return _main_impl() or 0
    except SystemExit:
        raise
    except KeyboardInterrupt:
        sys.stderr.write("Error: interrupted.\n")
        return 1
    except IsADirectoryError:
        sys.stderr.write("Error: input path is a directory, not a file.\n")
        return 1
    except FileNotFoundError as exc:
        sys.stderr.write("Error: input file not found: %s\n" % exc)
        return 1
    except PermissionError as exc:
        sys.stderr.write("Error: permission denied reading input: %s\n" % exc)
        return 1
    except UnicodeError as exc:
        sys.stderr.write("Error: input encoding could not be decoded (%s).\n" % exc)
        return 1
    except (ValueError, TypeError, KeyError, IndexError, AttributeError) as exc:
        sys.stderr.write("Error: input could not be parsed as valid telemetry "
                         "(%s: %s).\n" % (type(exc).__name__, exc))
        return 1
    except RecursionError:
        sys.stderr.write("Error: input is nested too deeply to parse safely.\n")
        return 1
    except MemoryError:
        sys.stderr.write("Error: input exhausted available memory; refusing to continue.\n")
        return 1
    except OSError as exc:
        sys.stderr.write("Error: could not read or write a file: %s\n" % exc)
        return 1
    except Exception as exc:
        sys.stderr.write("Error: unrecoverable problem processing this input "
                         "(%s: %s).\n" % (type(exc).__name__, exc))
        return 1

if __name__ == "__main__":
  sys.exit(main() or 0)