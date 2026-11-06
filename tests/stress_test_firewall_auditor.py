#!/usr/bin/env python3
"""stress_test_firewall_auditor.py - 30-Scenario Stress & Edge-Case Battery for firewall-acl-auditor

Executes 30 rigorous edge-case, corruption, boundary, fuzzing, and performance tests
against audit-firewall-rules.py to guarantee enterprise resilience.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict

# Resolve scripts path
BASE_DIR = Path(__file__).resolve().parent
REPO_DIR = BASE_DIR.parent
script_file = REPO_DIR / "scripts" / "audit-firewall-rules.py"
if not script_file.exists():
    script_file = REPO_DIR / "skills" / "firewall-acl-auditor" / "scripts" / "audit-firewall-rules.py"

import importlib.util
spec = importlib.util.spec_from_file_location("audit_firewall_rules", str(script_file))
module = importlib.util.module_from_spec(spec)
sys.modules["audit_firewall_rules"] = module
spec.loader.exec_module(module)

audit_rules = module.audit_rules
parse_cisco = module.parse_cisco
parse_fortigate = module.parse_fortigate
parse_mikrotik = module.parse_mikrotik
parse_normalized_json = module.parse_normalized_json
parse_port_range = module.parse_port_range
normalize_network = module.normalize_network
Sanitizer = module.Sanitizer
NormalizedRule = module.NormalizedRule


class TestSuite:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.results = []

    def record(self, test_num: int, name: str, passed: bool, detail: str = ""):
        status = "PASS" if passed else "FAIL"
        if passed:
            self.passed += 1
        else:
            self.failed += 1
        self.results.append((test_num, name, status, detail))
        print(f"[{status}] Test {test_num:02d}: {name} {f'- {detail}' if detail else ''}")


def run_tests():
    suite = TestSuite()
    print("==================================================================")
    print("  firewall-acl-auditor Comprehensive 38-Scenario Stress Test Suite")
    print("==================================================================")

    # Test 01: Empty Configuration
    try:
        findings, _ = audit_rules([], "cisco")
        suite.record(1, "Empty configuration list evaluated cleanly (0 findings)", len(findings) == 0)
    except Exception as exc:
        suite.record(1, "Empty configuration", False, str(exc))

    # Test 02: Whitespace and Comments Only
    try:
        cfg = "!\n! Cisco ASA Comments\n!\n   \n"
        rules = parse_cisco(cfg)
        suite.record(2, "Whitespace and comment lines parsed with 0 rules extracted", len(rules) == 0)
    except Exception as exc:
        suite.record(2, "Whitespace and comments", False, str(exc))

    # Test 03: Cisco ASA Shadowed Exact Match (Permit shadows Deny)
    try:
        cfg = """
access-list OUTSIDE-IN extended permit tcp any 10.0.0.0 255.255.255.0 eq 443
access-list OUTSIDE-IN extended deny tcp any 10.0.0.0 255.255.255.0 eq 443
"""
        rules = parse_cisco(cfg)
        findings, _ = audit_rules(rules, "cisco")
        shadowed = any(f.category == "SHADOWED_CONFLICT" and f.severity == "CRITICAL" for f in findings)
        suite.record(3, "Cisco ASA exact match permit shadowing deny detected (CRITICAL)", shadowed)
    except Exception as exc:
        suite.record(3, "Cisco ASA exact match shadowed", False, str(exc))

    # Test 04: Cisco ASA Subnet Superset Shadowing (/24 shadows /32)
    try:
        cfg = """
access-list OUTSIDE-IN extended permit ip any 10.0.0.0 255.255.255.0
access-list OUTSIDE-IN extended deny ip any host 10.0.0.50
"""
        rules = parse_cisco(cfg)
        findings, _ = audit_rules(rules, "cisco")
        shadowed = any(f.category == "SHADOWED_CONFLICT" for f in findings)
        suite.record(4, "Cisco ASA subnet superset (/24 permit shadows /32 deny) detected", shadowed)
    except Exception as exc:
        suite.record(4, "Cisco ASA subnet superset", False, str(exc))

    # Test 05: Cisco ASA Redundant Duplicate Rule
    try:
        cfg = """
access-list INSIDE-IN extended permit tcp any host 10.1.1.5 eq 443
access-list INSIDE-IN extended permit tcp any host 10.1.1.5 eq 443
"""
        rules = parse_cisco(cfg)
        findings, _ = audit_rules(rules, "cisco")
        redundant = any(f.category == "REDUNDANT_DUPLICATE" for f in findings)
        suite.record(5, "Cisco ASA redundant duplicate permit rule detected", redundant)
    except Exception as exc:
        suite.record(5, "Cisco ASA redundant rule", False, str(exc))

    # Test 06: Cisco ASA Permissive ANY-ANY Rule
    try:
        cfg = "access-list DMZ-IN extended permit ip any any"
        rules = parse_cisco(cfg)
        findings, _ = audit_rules(rules, "cisco")
        any_any = any(f.category == "PERMISSIVE_ANY_ANY" and f.severity == "CRITICAL" for f in findings)
        suite.record(6, "Cisco ASA PERMIT IP ANY ANY detected as CRITICAL Zero Trust violation", any_any)
    except Exception as exc:
        suite.record(6, "Cisco ASA permissive any-any", False, str(exc))

    # Test 07: Cisco ASA WAN Exposed SSH Port 22
    try:
        cfg = "access-list OUTSIDE-IN extended permit tcp any host 10.0.0.1 eq 22"
        rules = parse_cisco(cfg)
        findings, _ = audit_rules(rules, "cisco")
        ssh = any(f.category == "WAN_EXPOSED_MANAGEMENT_PORT" and "SSH" in f.description for f in findings)
        suite.record(7, "Exposed SSH port 22 to 0.0.0.0/0 flagged as high risk", ssh)
    except Exception as exc:
        suite.record(7, "Cisco ASA WAN exposed SSH", False, str(exc))

    # Test 08: Cisco ASA WAN Exposed RDP Port 3389
    try:
        cfg = "access-list OUTSIDE-IN extended permit tcp any any eq 3389"
        rules = parse_cisco(cfg)
        findings, _ = audit_rules(rules, "cisco")
        rdp = any(f.category == "WAN_EXPOSED_MANAGEMENT_PORT" and "RDP" in f.description for f in findings)
        suite.record(8, "Exposed RDP port 3389 to 0.0.0.0/0 flagged as high risk", rdp)
    except Exception as exc:
        suite.record(8, "Cisco ASA WAN exposed RDP", False, str(exc))

    # Test 09: Cisco ASA WAN Exposed SMB Port 445
    try:
        cfg = "access-list OUTSIDE-IN extended permit tcp any any eq 445"
        rules = parse_cisco(cfg)
        findings, _ = audit_rules(rules, "cisco")
        smb = any(f.category == "WAN_EXPOSED_MANAGEMENT_PORT" and "SMB" in f.description for f in findings)
        suite.record(9, "Exposed SMB port 445 to 0.0.0.0/0 flagged as lateral movement risk", smb)
    except Exception as exc:
        suite.record(9, "Cisco ASA WAN exposed SMB", False, str(exc))

    # Test 10: Cisco ASA Disabled Rule
    try:
        cfg = "access-list OUTSIDE-IN extended permit tcp any any eq 80 inactive"
        rules = parse_cisco(cfg)
        findings, _ = audit_rules(rules, "cisco")
        inactive = any(f.category == "DISABLED_RULE" for f in findings)
        suite.record(10, "Cisco ASA inactive rule flagged as dormant rule clutter", inactive)
    except Exception as exc:
        suite.record(10, "Cisco ASA disabled rule", False, str(exc))

    # Test 11: Cisco ASA Remediation CLI Generation
    try:
        cfg = """
access-list OUT line 1 permit ip any any
access-list OUT line 2 deny ip any host 10.0.0.1
"""
        rules = parse_cisco(cfg)
        findings, _ = audit_rules(rules, "cisco")
        finding = next(f for f in findings if f.category == "SHADOWED_CONFLICT")
        full_cli = "\n".join(finding.remediation_cli)
        has_cli = "no access-list" in full_cli or "resequence" in full_cli
        suite.record(11, "Cisco ASA remediation produces verified remediation CLI commands", has_cli)
    except Exception as exc:
        suite.record(11, "Cisco ASA remediation CLI", False, str(exc))

    # Test 12: FortiGate Shadowed Policy
    try:
        cfg = """
config firewall policy
    edit 10
        set name "Broad-Allow"
        set srcintf "wan1"
        set dstintf "internal"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
    next
    edit 20
        set name "Block-Subnet"
        set srcintf "wan1"
        set dstintf "internal"
        set srcaddr "all"
        set dstaddr "10.0.0.0/24"
        set action deny
        set schedule "always"
        set service "ALL"
    next
end
"""
        rules = parse_fortigate(cfg)
        findings, _ = audit_rules(rules, "fortigate")
        shadowed = any(f.category == "SHADOWED_CONFLICT" for f in findings)
        suite.record(12, "FortiGate policy 10 shadowing policy 20 detected", shadowed)
    except Exception as exc:
        suite.record(12, "FortiGate shadowed policy", False, str(exc))

    # Test 13: FortiGate Redundant Policy
    try:
        cfg = """
config firewall policy
    edit 10
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
    edit 20
        set srcaddr "all"
        set dstaddr "10.0.0.0/24"
        set action accept
        set service "ALL"
    next
end
"""
        rules = parse_fortigate(cfg)
        findings, _ = audit_rules(rules, "fortigate")
        redundant = any(f.category == "REDUNDANT_DUPLICATE" for f in findings)
        suite.record(13, "FortiGate policy 20 redundant to broad policy 10 detected", redundant)
    except Exception as exc:
        suite.record(13, "FortiGate redundant policy", False, str(exc))

    # Test 14: FortiGate Disabled Status
    try:
        cfg = """
config firewall policy
    edit 5
        set status disable
        set srcaddr "all"
        set dstaddr "all"
        set action accept
    next
end
"""
        rules = parse_fortigate(cfg)
        findings, _ = audit_rules(rules, "fortigate")
        disabled = any(f.category == "DISABLED_RULE" for f in findings)
        suite.record(14, "FortiGate 'set status disable' flagged as disabled rule", disabled)
    except Exception as exc:
        suite.record(14, "FortiGate disabled status", False, str(exc))

    # Test 15: FortiGate All-All Permissive Service
    try:
        cfg = """
config firewall policy
    edit 1
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
end
"""
        rules = parse_fortigate(cfg)
        findings, _ = audit_rules(rules, "fortigate")
        permissive = any(f.category == "PERMISSIVE_ANY_ANY" for f in findings)
        suite.record(15, "FortiGate accept all to all flags PERMISSIVE_ANY_ANY", permissive)
    except Exception as exc:
        suite.record(15, "FortiGate all-all permissive", False, str(exc))

    # Test 16: FortiGate Remediation CLI Generation
    try:
        cfg = """
config firewall policy
    edit 10
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "ALL"
    next
    edit 20
        set srcaddr "all"
        set dstaddr "10.0.0.0/24"
        set action accept
        set service "ALL"
    next
end
"""
        rules = parse_fortigate(cfg)
        findings, _ = audit_rules(rules, "fortigate")
        finding = next(f for f in findings if f.category == "REDUNDANT_DUPLICATE")
        full_cli = "\n".join(finding.remediation_cli)
        has_cli = "config firewall policy" in full_cli and "delete 20" in full_cli
        suite.record(16, "FortiGate remediation generates 'delete <id>' config block", has_cli)
    except Exception as exc:
        suite.record(16, "FortiGate remediation CLI", False, str(exc))

    # Test 17: MikroTik RouterOS Shadowed Filter Rule
    try:
        cfg = """
/ip firewall filter
add action=accept chain=forward comment="Allow-All" src-address=0.0.0.0/0 dst-address=0.0.0.0/0
add action=drop chain=forward comment="Drop-Internal" src-address=10.0.0.0/24 dst-address=192.168.1.0/24
"""
        rules = parse_mikrotik(cfg)
        findings, _ = audit_rules(rules, "mikrotik")
        shadowed = any(f.category == "SHADOWED_CONFLICT" for f in findings)
        suite.record(17, "MikroTik forward chain rule shadowing drop rule detected", shadowed)
    except Exception as exc:
        suite.record(17, "MikroTik shadowed rule", False, str(exc))

    # Test 18: MikroTik Missing Explicit Drop Rule
    try:
        cfg = """
/ip firewall filter
add action=accept chain=input comment="Allow-SSH" dst-port=22 protocol=tcp
add action=accept chain=input comment="Allow-DNS" dst-port=53 protocol=udp
"""
        rules = parse_mikrotik(cfg)
        findings, _ = audit_rules(rules, "mikrotik")
        missing_drop = any(f.category == "MISSING_EXPLICIT_DROP_MIKROTIK" for f in findings)
        suite.record(18, "MikroTik chain lacking terminal drop flagged (prevents default accept leak)", missing_drop)
    except Exception as exc:
        suite.record(18, "MikroTik missing explicit drop", False, str(exc))

    # Test 19: MikroTik Terminal Drop Present
    try:
        cfg = """
/ip firewall filter
add action=accept chain=input comment="Allow-SSH" dst-port=22 protocol=tcp
add action=drop chain=input comment="Drop-All-Other-Input"
"""
        rules = parse_mikrotik(cfg)
        findings, _ = audit_rules(rules, "mikrotik")
        missing_drop = any(f.category == "MISSING_EXPLICIT_DROP_MIKROTIK" for f in findings)
        suite.record(19, "MikroTik chain with terminal drop rule avoids missing drop alert", not missing_drop)
    except Exception as exc:
        suite.record(19, "MikroTik terminal drop present", False, str(exc))

    # Test 20: MikroTik WinBox Port 8291 WAN Exposure
    try:
        cfg = """
/ip firewall filter
add action=accept chain=input comment="WinBox-Anywhere" dst-port=8291 protocol=tcp
"""
        rules = parse_mikrotik(cfg)
        findings, _ = audit_rules(rules, "mikrotik")
        winbox = any("MikroTik-WinBox" in f.description for f in findings)
        suite.record(20, "MikroTik WinBox management port 8291 exposure flagged as high risk", winbox)
    except Exception as exc:
        suite.record(20, "MikroTik WinBox exposure", False, str(exc))

    # Test 21: MikroTik Remediation CLI Generation
    try:
        cfg = """
/ip firewall filter
add action=accept chain=forward comment="Broad-Rule" src-address=0.0.0.0/0 dst-address=0.0.0.0/0
add action=accept chain=forward comment="Redundant-Sub" src-address=10.0.0.0/24 dst-address=10.0.0.0/24
"""
        rules = parse_mikrotik(cfg)
        findings, _ = audit_rules(rules, "mikrotik")
        finding = next(f for f in findings if f.category == "REDUNDANT_DUPLICATE")
        has_cli = any("/ip firewall filter remove" in cmd for cmd in finding.remediation_cli)
        suite.record(21, "MikroTik remediation produces '/ip firewall filter remove' command", has_cli)
    except Exception as exc:
        suite.record(21, "MikroTik remediation CLI", False, str(exc))

    # Test 22: Inverted Port Range Normalization
    try:
        r_start, r_end = parse_port_range("8080-80")
        suite.record(22, "Inverted port range '8080-80' normalized to (80, 8080)", r_start == 80 and r_end == 8080)
    except Exception as exc:
        suite.record(22, "Inverted port range", False, str(exc))

    # Test 23: Out of Bounds Port Clamped
    try:
        r_start, r_end = parse_port_range("99999")
        suite.record(23, "Out-of-bounds port 99999 safely clamped to 65535", r_start == 65535 and r_end == 65535)
    except Exception as exc:
        suite.record(23, "Out of bounds port", False, str(exc))

    # Test 24: Fuzzed JSON Dict Wrapper Parsing
    try:
        json_txt = json.dumps({"rules": [{"rule_id": "R1", "action": "permit", "protocol": "tcp", "src_cidr": "0.0.0.0/0", "dst_cidr": "0.0.0.0/0", "dst_port": "443"}]})
        rules = parse_normalized_json(json_txt)
        suite.record(24, "Fuzzed JSON wrapped in {'rules': [...]} parsed successfully", len(rules) == 1)
    except Exception as exc:
        suite.record(24, "Fuzzed JSON dict wrapper", False, str(exc))

    # Test 25: Fuzzed JSON Missing Prefixes
    try:
        json_txt = json.dumps([{"rule_id": "R1", "src_prefixes": [], "dst_prefixes": [], "dst_ports": []}])
        rules = parse_normalized_json(json_txt)
        suite.record(25, "Fuzzed JSON with empty prefix arrays defaults safely to 0.0.0.0/0", len(rules) == 1 and rules[0].src_cidr == "0.0.0.0/0")
    except Exception as exc:
        suite.record(25, "Fuzzed JSON missing prefixes", False, str(exc))

    # Test 26: Sanitization RFC 5737 Test Prefixes
    try:
        san = Sanitizer()
        masked_ip = san.sanitize_ip_or_cidr("10.50.20.1/32")
        valid = masked_ip.startswith("198.51.100.")
        suite.record(26, "Sanitizer maps private IPv4 host to RFC 5737 test address (198.51.100.x)", valid)
    except Exception as exc:
        suite.record(26, "Sanitization RFC 5737", False, str(exc))

    # Test 27: Sanitization Scrubs Pre-Shared Keys & Passwords
    try:
        san = Sanitizer()
        raw = "set preshared-key \"MySecretCorporateKey!123\" and community PublicString123"
        clean = san.scrub_secrets(raw)
        valid = "[REDACTED-SECRET]" in clean and "MySecretCorporateKey!123" not in clean and "PublicString123" not in clean
        suite.record(27, "Sanitizer scrubs pre-shared-keys and SNMP community strings", valid)
    except Exception as exc:
        suite.record(27, "Sanitization scrubs secrets", False, str(exc))

    # Test 28: Cross-ACL Chain Isolation
    try:
        cfg = """
access-list OUTSIDE-IN extended permit ip any any
access-list INSIDE-IN extended deny ip any any
"""
        rules = parse_cisco(cfg)
        findings, _ = audit_rules(rules, "cisco")
        shadowed = any(f.category == "SHADOWED_CONFLICT" for f in findings)
        suite.record(28, "Rules in distinct ACLs (OUTSIDE-IN vs INSIDE-IN) never shadow each other", not shadowed)
    except Exception as exc:
        suite.record(28, "Cross-ACL isolation", False, str(exc))

    # Test 29: Different Protocol Isolation (TCP vs UDP)
    try:
        cfg = """
access-list OUT extended permit tcp any host 10.0.0.1 eq 53
access-list OUT extended deny udp any host 10.0.0.1 eq 53
"""
        rules = parse_cisco(cfg)
        findings, _ = audit_rules(rules, "cisco")
        shadowed = any(f.category == "SHADOWED_CONFLICT" for f in findings)
        suite.record(29, "TCP permit rule does not shadow UDP deny rule on identical IP and port", not shadowed)
    except Exception as exc:
        suite.record(29, "Different protocol isolation", False, str(exc))

    # Test 30: Large Ruleset Performance Benchmark (500 Rules)
    try:
        large_rules = [
            NormalizedRule(
                vendor="cisco",
                chain_or_acl="BIG-ACL",
                seq_or_id=str(i),
                action="permit" if i % 5 != 0 else "deny",
                protocol="tcp",
                src_cidr=f"10.{(i // 256) % 256}.{i % 256}.0/24",
                dst_cidr="172.16.0.0/16",
                dst_port=str(80 + (i % 100)),
                enabled=True,
                raw_line=f"access-list BIG-ACL line {i} permit tcp 10.0.{i % 256}.0 255.255.255.0 172.16.0.0 255.255.0.0 eq {80 + (i % 100)}"
            )
            for i in range(500)
        ]
        start = time.perf_counter()
        findings, _ = audit_rules(large_rules, "cisco")
        elapsed = time.perf_counter() - start
        suite.record(30, f"Large ruleset benchmark (500 rules pairwise audit in {elapsed:.3f}s)", elapsed < 1.0, f"Pairs checked: {500*499//2:,}")
    except Exception as exc:
        suite.record(30, "Large ruleset benchmark", False, str(exc))

    # Test 31: MikroTik Connection-State Established Filter Not Flagged as ANY-ANY
    try:
        cfg = """
/ip firewall filter
add action=accept chain=forward comment="Established-Related" connection-state=established,related
"""
        rules = parse_mikrotik(cfg)
        findings, _ = audit_rules(rules, "mikrotik")
        any_any = any(f.category == "PERMISSIVE_ANY_ANY" for f in findings)
        suite.record(31, "MikroTik established/related connection tracking rule is not false-positive ANY-ANY", not any_any)
    except Exception as exc:
        suite.record(31, "MikroTik established filter", False, str(exc))

    # Test 32: MikroTik Connection-State Established Does Not Shadow Forward Drop
    try:
        cfg = """
/ip firewall filter
add action=accept chain=forward comment="Established-Traffic" connection-state=established,related
add action=drop chain=forward comment="Drop-Bad-Subnet" src-address=192.168.1.0/24
"""
        rules = parse_mikrotik(cfg)
        findings, _ = audit_rules(rules, "mikrotik")
        shadowed = any(f.category == "SHADOWED_CONFLICT" for f in findings)
        suite.record(32, "MikroTik established stateful rule does not falsely shadow subsequent drop rule", not shadowed)
    except Exception as exc:
        suite.record(32, "MikroTik stateful shadowing", False, str(exc))

    # Test 33: Multiport Comma-Separated List (80,443) Isolation
    try:
        r1 = NormalizedRule("generic", "ACL", "1", "permit", "tcp", "0.0.0.0/0", "0.0.0.0/0", "80,443", True, "rule 1")
        r2 = NormalizedRule("generic", "ACL", "2", "deny", "tcp", "0.0.0.0/0", "0.0.0.0/0", "22", True, "rule 2")
        findings, _ = audit_rules([r1, r2], "generic")
        shadowed = any(f.category == "SHADOWED_CONFLICT" for f in findings)
        suite.record(33, "Multiport rule (80,443) does not false-positive shadow port 22", not shadowed)
    except Exception as exc:
        suite.record(33, "Multiport port 22 isolation", False, str(exc))

    # Test 34: Broad Port Range Shadows Multiport Subset
    try:
        r1 = NormalizedRule("generic", "ACL", "1", "permit", "tcp", "0.0.0.0/0", "0.0.0.0/0", "80-500", True, "rule 1")
        r2 = NormalizedRule("generic", "ACL", "2", "deny", "tcp", "0.0.0.0/0", "0.0.0.0/0", "80,443", True, "rule 2")
        findings, _ = audit_rules([r1, r2], "generic")
        shadowed = any(f.category == "SHADOWED_CONFLICT" for f in findings)
        suite.record(34, "Broad port range (80-500) correctly shadows multiport subset (80,443)", shadowed)
    except Exception as exc:
        suite.record(34, "Broad port range shadowing multiport", False, str(exc))

    # Test 35: Narrow Port Does Not Shadow Multiport Rule
    try:
        r1 = NormalizedRule("generic", "ACL", "1", "permit", "tcp", "0.0.0.0/0", "0.0.0.0/0", "80", True, "rule 1")
        r2 = NormalizedRule("generic", "ACL", "2", "deny", "tcp", "0.0.0.0/0", "0.0.0.0/0", "80,443", True, "rule 2")
        findings, _ = audit_rules([r1, r2], "generic")
        shadowed = any(f.category == "SHADOWED_CONFLICT" for f in findings)
        suite.record(35, "Narrow port (80) does not shadow multiport rule (80,443)", not shadowed)
    except Exception as exc:
        suite.record(35, "Narrow port does not shadow multiport", False, str(exc))

    # Test 36: FortiGate Multiple Quoted Services
    try:
        cfg = """
config firewall policy
    edit 10
        set name "Web-Services"
        set srcintf "lan"
        set dstintf "wan"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set service "HTTP" "HTTPS"
    next
end
"""
        rules = parse_fortigate(cfg)
        r = rules[0]
        valid = "80" in r.dst_port and "443" in r.dst_port and r.dst_port != "any"
        suite.record(36, "FortiGate multiple quoted services ('HTTP' 'HTTPS') parsed into port list (80,443)", valid)
    except Exception as exc:
        suite.record(36, "FortiGate multiple services", False, str(exc))

    # Test 37: Cisco Wildcard Mask Inversion (0.0.255.255 to /16)
    try:
        cfg = """
access-list IN extended permit ip 10.1.0.0 0.0.255.255 any
"""
        rules = parse_cisco(cfg)
        suite.record(37, "Cisco IOS wildcard mask (10.1.0.0 0.0.255.255) converted to CIDR 10.1.0.0/16", rules[0].src_cidr == "10.1.0.0/16")
    except Exception as exc:
        suite.record(37, "Cisco wildcard mask inversion", False, str(exc))

    # Test 38: Inactive / Disabled Rule Shadows No One
    try:
        cfg = """
access-list IN extended permit ip any any inactive
access-list IN extended deny ip 10.0.0.0 255.0.0.0 any
"""
        rules = parse_cisco(cfg)
        findings, _ = audit_rules(rules, "cisco")
        shadowed = any(f.category == "SHADOWED_CONFLICT" for f in findings)
        suite.record(38, "Inactive rule does not participate in shadowing active deny rules", not shadowed)
    except Exception as exc:
        suite.record(38, "Inactive rule shadowing exclusion", False, str(exc))

    print("==================================================================")
    print(f"  STRESS TEST SUMMARY: {suite.passed} PASSED, {suite.failed} FAILED out of {len(suite.results)} tests")
    print("==================================================================")

    if suite.failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
