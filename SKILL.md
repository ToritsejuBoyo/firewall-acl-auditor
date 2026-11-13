---
name: firewall-acl-auditor
description: >-
  Audit multi-vendor firewall and router ACL configurations (Cisco IOS/IOS-XE/ASA, Fortinet
  FortiGate FortiOS, and MikroTik RouterOS v6/v7) to detect shadowed rules, redundant entries,
  overly permissive ANY-ANY rules, high-risk exposed management ports, and missing logging, and
  generate vendor-accurate remediation CLI scripts with rollback commands. Use whenever a network
  or security engineer needs to review firewall configs, clean up legacy ACLs, or convert rules
  across Cisco, FortiGate, and MikroTik.
license: MIT
version: 1.0.0
metadata:
  standard: agentskills.io
  dependencies: none (Python standard library only)
  access: read-only collectors; no state is modified on target systems
---

# Multi-Vendor Firewall & ACL Conflict Auditor (`firewall-acl-auditor`)

## Purpose & Target Roles
Built for **Network Engineers, Network Administrators, NOC Engineers, and Security Operations / Firewall Engineers** across enterprises, MSPs, and SMEs. Over years of emergency tickets, firewall rulebases accumulate shadowed rules (rules placed *after* a broader permit/deny that can never match packets), redundant duplicates, dangerous `permit ip any any` temporary rules, and unlogged drops. This skill pairs a deterministic multi-vendor rule parser (`scripts/audit-firewall-rules.py`) with vendor-accurate remediation and rollback generation across **Cisco IOS/ASA**, **Fortinet FortiGate**, and **MikroTik RouterOS**.

## Operating Rules & Safety Guardrails
1. **Top-Down First-Match Determinism:** All three target platforms (Cisco ACLs, FortiGate firewall policies, and MikroTik `/ip firewall filter` chains) evaluate rules **top-to-bottom (first match wins)** within a given ACL/chain/interface pair. Never reorder rules without calculating whether intermediate `deny`/`drop` exceptions will be bypassed.
2. **Anti-Lockout Protection (Mandatory):** Before outputting any CLI script that deletes, disables, or reorders rules, explicitly verify that administrative access (`SSH TCP/22`, `HTTPS TCP/443/8443`, `WinBox TCP/8291`) from the management subnet is preserved, and include platform-specific auto-rollback timers (`reload in 10` on Cisco IOS, `cfg-save revert` on FortiOS, **Safe Mode** `Ctrl+X` on MikroTik RouterOS).
3. **Zero-Hit Count Verification:** Always instruct the engineer to verify hit counters (`hitcnt=0`, bytes/packets = `0`) over a full business cycle (minimum 7–30 days) before deleting a suspected stale rule in production.
4. **Sanitization & Proof-of-Work Support:** Support public IP / description redaction via `--sanitize` and portfolio case-study generation via `--generate-proof-of-work`.

---

## Step 1: Configuration Input Acquisition

Accept any of the following inputs:
1. **Pre-Parsed Audit Output from Bundled Python Script (Preferred):**
   ```bash
   python scripts/audit-firewall-rules.py --input firewall-config.txt --vendor auto --sanitize --format markdown
   ```
2. **Raw CLI Config Exports (Pasted or Uploaded):**
   - **Cisco IOS / IOS-XE:** `show ip access-lists` or `show running-config | section ip access-list`
   - **Cisco ASA / Firepower Threat Defense (LINA):** `show access-list` or `show running-config access-list`
   - **Fortinet FortiGate (FortiOS):** `show firewall policy` or `show full-configuration firewall policy`
   - **MikroTik RouterOS (v6 / v7):** `/ip firewall filter export terse` or `/ip firewall filter print stats detail`

---

## Step 2: Multi-Step Audit & Conflict Detection Workflow

Execute the following 5-stage analysis on the normalized rule table (referencing `references/vendor-acl-syntax-and-conflict-matrix.md`):

### Stage 1: Vendor, Chain & Implicit Default Identification
1. Identify the vendor OS, ACL name / interface direction (`in`/`out`), or MikroTik chain (`input` = traffic to router itself, `forward` = traffic routed through router, `output` = router-originated traffic).
2. Check how the ACL/chain terminates:
   - **Cisco IOS / ASA & FortiGate:** End with an **implicit `deny ip any any`** (which often drops silently without logging unless an explicit logged deny rule is placed at the bottom).
   - **MikroTik RouterOS:** Ends with an **implicit `accept` (permit all)**! Flag any MikroTik `input` or `forward` chain that lacks an explicit final `action=drop` rule as a **Critical Security Finding**.

### Stage 2: Mathematical Shadowing & Redundancy Analysis
Compare every rule $R_j$ (at lower priority / higher line number $j$) against every preceding rule $R_i$ ($i < j$) within the same ACL, chain, or `(srcintf, dstintf)` pair:
1. **Exact Duplicate / Redundant Permit-Permit or Deny-Deny:**
   - If $R_i$ and $R_j$ have identical `(Action, Protocol, SrcCIDR, DstCIDR, DstPort)` or $R_j \subseteq R_i$ with the **same action**, flag $R_j$ as **Redundant (Safe to Remove)**.
2. **Shadowed Conflict (Opposite Action — Critical):**
   - If $R_j \subseteq R_i$ (i.e., $R_i$'s protocol, source subnet, destination subnet, and port range completely encompass $R_j$) AND $\text{Action}(R_i) \neq \text{Action}(R_j)$:
     - **Case A (`Permit` precedes specific `Deny`):** **CRITICAL SECURITY BYPASS.** A broad `permit` at line $i$ allows traffic that the administrator intended to block at line $j$.
     - **Case B (`Deny` precedes specific `Permit`):** **OPERATIONAL OUTAGE / DEAD RULE.** A broad `deny` at line $i$ blocks traffic that line $j$ was meant to allow.

### Stage 3: High-Risk Exposure & Overly Permissive Rule Audit
Scan all `permit` / `accept` rules for:
1. **Unrestricted `ANY-ANY` Permits:** Source `0.0.0.0/0` (`any`) to Destination `0.0.0.0/0` (`any`) on `ip`/`all` protocols.
2. **WAN-Exposed Management & Infrastructure Services:** Any rule permitting source `0.0.0.0/0` (or WAN interface) to reach:
   - `TCP/22` (SSH), `TCP/23` (Telnet), `TCP/3389` (RDP), `TCP/445` (SMB), `TCP/8291` (MikroTik WinBox), `TCP/8728-8729` (MikroTik API), `TCP/161-162` (SNMP), `TCP/1433, 3306, 5432` (Databases).
3. **Disabled / Commented / Temporary Rules (`TEMP`, `TEST`, `TICKET-`):** Flag disabled rules or rules with expired ticket comments for cleanup.
4. **Missing Security Profiles / Logging:** On FortiGate, check if `utm-status` / `av-profile` / `ips-sensor` or `logtraffic all` is missing on internet-facing policies. On Cisco/MikroTik, check if final drop rules lack `log` / `log=yes`.

### Stage 4: Vendor-Accurate Remediation & Rollback Synthesis
Generate exact, copy-paste CLI commands for the detected platform:
- **Reordering Fixes:** Move specific `deny` or `permit` exception rules *above* broader summary rules (`ip access-list resequence` on Cisco IOS, `config firewall policy -> move <id> before <id>` on FortiGate, `/ip firewall filter move <numbers> destination=<index>` on MikroTik).
- **Safe Rollback Block:** Provide the exact one-for-one inverse commands to restore the previous rule order or re-insert deleted lines if an application breaks.

---

## Step 3: Structured Deliverable Generation
Populate and return the report following `assets/firewall-audit-remediation-template.md`.

---

## Step 4: Portfolio / Proof-of-Work Mode (`--generate-proof-of-work`)
If `--generate-proof-of-work` is requested:
1. Mask all public IPv4/IPv6 addresses, customer names, and interface descriptions.
2. Append a **"Verified Network Security Audit Case Study"** summarizing total rules audited, shadowed conflicts resolved, attack surface reduction achieved, and zero-downtime change execution.

## Bundled Resources Reference
- **Auditor Script:** `scripts/audit-firewall-rules.py` (Zero-dependency Python 3 parser supporting Cisco IOS/ASA, FortiGate, and MikroTik RouterOS with CIDR subset math).
- **Technical Reference:** `references/vendor-acl-syntax-and-conflict-matrix.md` (Cross-vendor syntax translation, implicit end-of-chain behavior, and anti-lockout commands).
- **Output Template:** `assets/firewall-audit-remediation-template.md` (Standard firewall audit report and CAB remediation script template).

---

## Data Handling & Sanitization

Sanitization runs **client-side, before any output is produced**, so credentials and
personal data are removed on the operator's machine rather than being sent to a model
or pasted into a ticket.

Two layers apply:

1. This skill's own domain-aware masking (hostnames, accounts, and the identifiers
   specific to this domain).
2. A shared residual pass, [`scripts/sanitizer.py`](scripts/sanitizer.py), vendored
   identically across every skill in the library. It is the common floor: private keys,
   cloud provider keys, JWTs and bearer tokens, connection-string passwords, assigned
   secrets, emails, IPv4/IPv6 addresses, MAC addresses, GUIDs, SSNs, payment card
   numbers, and phone numbers.

This skill runs the shared pass with IPv4/IPv6 redaction disabled, because addresses and subnets are the subject of the audit - masking them would make the findings meaningless. Its own vendor-aware masking still applies to addresses, and credential redaction is unaffected.

The contract is enforced by `tests/sanitizer_conformance_test.py`, which runs the same
adversarial corpus in every skill. Documentation placeholders (RFC 5737/3849 addresses,
RFC 7042 MAC ranges, `example.com` names, and existing `[REDACTED-*]` tokens) are
preserved, so the pass is safe to apply more than once.

Sanitization is thorough and tested, but it is not a substitute for reading output
before sharing it outside your organization.
