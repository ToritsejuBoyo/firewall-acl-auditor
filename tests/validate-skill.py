#!/usr/bin/env python3
"""Automated Validation Harness for Multi-Vendor Firewall & ACL Auditor (validate-skill.py)

Executes 7 deterministic validation suites to verify:
1. Cisco ASA / IOS ACL parser, shadowing, and redundancy detection.
2. Fortinet FortiGate firewall policy parser, reordering, and rollback generation.
3. MikroTik RouterOS filter parser and implicit accept end-of-chain detection.
4. Normalized multi-vendor JSON table ingestion.
5. Bitwise CIDR and port space containment mathematical precision.
6. Data sanitization (RFC 5737 test prefixes) and secret scrubbing.
7. agentskills.io SKILL.md specification and zero-dependency compliance.

Returns exit code 0 on 100% test pass.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT_DIR = Path(__file__).resolve().parent.parent
SCRIPT_PATH = ROOT_DIR / "scripts" / "audit-firewall-rules.py"
FIXTURES_DIR = ROOT_DIR / "tests" / "fixtures"
SKILL_MD = ROOT_DIR / "SKILL.md"


class TestFirewallAclAuditor(unittest.TestCase):

  @classmethod
  def setUpClass(cls):
    # Dynamically import audit-firewall-rules.py as module
    spec = importlib.util.spec_from_file_location(
        "audit_fw", str(SCRIPT_PATH)
    )
    cls.fw = importlib.util.module_from_spec(spec)
    sys.modules["audit_fw"] = cls.fw
    spec.loader.exec_module(cls.fw)

  def test_01_cisco_asa_audit(self):
    """Suite 1: Validate Cisco ASA ACL parsing, shadowing, redundancy, and any-any detection."""
    fixture = FIXTURES_DIR / "fixture-cisco-asa-shadowed.txt"
    content = fixture.read_text(encoding="utf-8")
    rules = self.fw.parse_cisco(content)
    self.assertEqual(len(rules), 6, "Expected 6 Cisco ACL rules parsed")

    findings, sanitizer = self.fw.audit_rules(rules, sanitize=False)
    self.assertEqual(len(findings), 5, "Expected 5 distinct findings")

    categories = {f.category for f in findings}
    self.assertIn("DISABLED_RULE", categories)
    self.assertIn("SHADOWED_CONFLICT", categories)
    self.assertIn("REDUNDANT_DUPLICATE", categories)
    self.assertIn("WAN_EXPOSED_MANAGEMENT_PORT", categories)
    self.assertIn("PERMISSIVE_ANY_ANY", categories)

    # Validate shadow details
    shadow = next(f for f in findings if f.category == "SHADOWED_CONFLICT")
    self.assertEqual(shadow.rule_id, "20")
    self.assertEqual(shadow.conflicting_rule_id, "10")
    self.assertEqual(shadow.severity, "CRITICAL")
    self.assertTrue(
        any("resequence" in cmd for cmd in shadow.remediation_cli),
        "Expected Cisco resequence command in remediation",
    )

  def test_02_fortigate_policy_audit(self):
    """Suite 2: Validate Fortinet FortiGate policy parser, reordering, and rollback generation."""
    fixture = FIXTURES_DIR / "fixture-fortigate-redundant.txt"
    content = fixture.read_text(encoding="utf-8")
    rules = self.fw.parse_fortigate(content)
    self.assertEqual(len(rules), 6, "Expected 6 FortiGate policies parsed")

    findings, sanitizer = self.fw.audit_rules(rules, sanitize=False)
    self.assertEqual(
        len(findings), 5, "Expected 5 distinct FortiGate findings"
    )

    shadow = next(f for f in findings if f.category == "SHADOWED_CONFLICT")
    self.assertEqual(shadow.rule_id, "30")
    self.assertEqual(shadow.conflicting_rule_id, "10")
    self.assertIn(
        "move 30 before 10",
        "\n".join(shadow.remediation_cli),
        "Expected FortiGate 'move 30 before 10' command",
    )
    self.assertIn(
        "move 30 after 10",
        "\n".join(shadow.rollback_cli),
        "Expected FortiGate rollback command",
    )

    redundant = next(
        f for f in findings if f.category == "REDUNDANT_DUPLICATE"
    )
    self.assertEqual(redundant.rule_id, "20")
    self.assertIn("delete 20", "\n".join(redundant.remediation_cli))

  def test_03_mikrotik_implicit_drop_and_filters(self):
    """Suite 3: Validate MikroTik filter parsing, shadowing, and implicit drop check."""
    fixture = FIXTURES_DIR / "fixture-mikrotik-any-any.rsc"
    content = fixture.read_text(encoding="utf-8")
    rules = self.fw.parse_mikrotik(content)
    self.assertEqual(len(rules), 6, "Expected 6 MikroTik rules parsed")

    findings, sanitizer = self.fw.audit_rules(rules, sanitize=False)
    self.assertEqual(len(findings), 6, "Expected 6 MikroTik findings")

    implicit = next(
        f for f in findings if f.category == "MISSING_EXPLICIT_DROP_MIKROTIK"
    )
    self.assertEqual(implicit.severity, "CRITICAL")
    self.assertIn(
        "action=drop",
        "\n".join(implicit.remediation_cli),
        "Expected explicit drop rule generated for MikroTik chain",
    )

  def test_04_normalized_json_ingestion(self):
    """Suite 4: Validate normalized multi-vendor JSON table ingestion."""
    fixture = FIXTURES_DIR / "fixture-normalized-multivendor.json"
    content = fixture.read_text(encoding="utf-8")
    rules = self.fw.parse_normalized_json(content)
    self.assertEqual(len(rules), 6, "Expected 6 normalized rules parsed")

    findings, _ = self.fw.audit_rules(rules, sanitize=False)
    self.assertEqual(len(findings), 5, "Expected 5 findings from JSON rules")

  def test_05_subnet_and_port_containment_math(self):
    """Suite 5: Validate mathematical bitwise CIDR and port space containment."""
    # Subnet containment tests
    net_super = self.fw.normalize_network("10.0.0.0/16")
    net_sub = self.fw.normalize_network("10.0.5.0/24")
    net_disjoint = self.fw.normalize_network("10.1.0.0/16")

    self.assertTrue(
        net_sub.subnet_of(net_super),
        "10.0.5.0/24 must be a subnet of 10.0.0.0/16",
    )
    self.assertFalse(
        net_super.subnet_of(net_sub),
        "10.0.0.0/16 must NOT be a subnet of 10.0.5.0/24",
    )
    self.assertFalse(
        net_disjoint.subnet_of(net_super),
        "10.1.0.0/16 must NOT be a subnet of 10.0.0.0/16",
    )

    # Any / internet containment
    any_net = self.fw.normalize_network("0.0.0.0/0")
    self.assertTrue(
        net_super.subnet_of(any_net), "Any subnet must be contained in 0.0.0.0/0"
    )

    # Port containment tests
    self.assertTrue(
        self.fw.is_port_superset("any", "443"),
        "Port 'any' must contain port 443",
    )
    self.assertTrue(
        self.fw.is_port_superset("1024-65535", "8080"),
        "Port range 1024-65535 must contain 8080",
    )
    self.assertFalse(
        self.fw.is_port_superset("80", "443"),
        "Port 80 must NOT contain port 443",
    )
    self.assertFalse(
        self.fw.is_port_superset("1024-2000", "8080"),
        "Range 1024-2000 must NOT contain 8080",
    )

  def test_06_data_sanitization_and_secret_scrubbing(self):
    """Suite 6: Validate RFC 5737 subnet mapping and secret scrubbing (Rule 4)."""
    sanitizer = self.fw.Sanitizer()

    # Secret scrubbing
    secret_text = (
        'set pre-shared-key "TopSecretPassword123"\nset password "AdminSecret!"'
    )
    scrubbed = sanitizer.scrub_secrets(secret_text)
    self.assertNotIn("TopSecretPassword123", scrubbed)
    self.assertNotIn("AdminSecret!", scrubbed)
    self.assertIn("[REDACTED-SECRET]", scrubbed)

    # IP Sanitization
    raw_ip = "10.250.15.1"
    masked = sanitizer.sanitize_ip_or_cidr(raw_ip)
    self.assertTrue(
        masked.startswith("198.51.100.") or masked.startswith("192.0.2."),
        f"Expected RFC 5737 test IP, got {masked}",
    )

  def test_07_agentskills_specification_and_dependencies(self):
    """Suite 7: Verify SKILL.md metadata, agentskills.io conformity, and zero external packages."""
    self.assertTrue(SKILL_MD.exists(), "SKILL.md must exist in root directory")
    skill_text = SKILL_MD.read_text(encoding="utf-8")

    # Frontmatter check
    self.assertTrue(skill_text.startswith("---"), "SKILL.md must have YAML frontmatter")
    self.assertIn("name: firewall-acl-auditor", skill_text)
    self.assertIn("description:", skill_text)

    # Rule 3 check: Zero third-party packages in scripts
    with open(SCRIPT_PATH, "r", encoding="utf-8") as f:
      code = f.read()

    forbidden_packages = [
        "requests",
        "netmiko",
        "paramiko",
        "napalm",
        "pandas",
        "scapy",
    ]
    for pkg in forbidden_packages:
      self.assertNotIn(
          f"import {pkg}", code, f"Forbidden external dependency: {pkg}"
      )
      self.assertNotIn(
          f"from {pkg}", code, f"Forbidden external dependency: {pkg}"
      )


def main():
  print("======================================================================")
  print("Running Automated Verification Suite for firewall-acl-auditor")
  print("======================================================================")
  suite = unittest.TestLoader().loadTestsFromTestCase(TestFirewallAclAuditor)
  runner = unittest.TextTestRunner(verbosity=2)
  result = runner.run(suite)
  if result.wasSuccessful():
    print("\nAll 7 verification suites passed successfully (Exit code: 0).")
    return 0
  else:
    print(
        f"\nVerification failed: {len(result.failures)} failures,"
        f" {len(result.errors)} errors."
    )
    return 1


if __name__ == "__main__":
  sys.exit(main())
