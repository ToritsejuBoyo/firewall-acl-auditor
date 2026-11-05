# Multi-Vendor Firewall & ACL Syntax, Implicit Behavior & Conflict Matrix Reference

This reference guides `firewall-acl-auditor` across **Cisco IOS/IOS-XE/ASA**, **Fortinet FortiGate (FortiOS)**, and **MikroTik RouterOS (v6 & v7)**.

---

## 1. Cross-Vendor Architecture & Implicit End-of-Policy Behavior

| Feature / Behavior | Cisco IOS / IOS-XE | Cisco ASA / FTD (LINA) | Fortinet FortiGate (FortiOS) | MikroTik RouterOS (v6 / v7) |
| --- | --- | --- | --- | --- |
| **Evaluation Order** | Top-down, first match wins (by sequence number `10, 20, 30`). | Top-down, first match wins (by `line 1, 2, 3`). | Top-down, first match wins (by policy order in table, **not** numeric policy ID). | Top-down, first match wins within each `chain` (`input`, `forward`, `output`). |
| **Mask Notation** | **Wildcard mask** (`0.0.0.255` = `/24`, `0.0.0.0` = `/32`). | **Subnet mask** (`255.255.255.0` = `/24`). | Address objects (`subnet 10.1.1.0 255.255.255.0`) or CIDR (`10.1.1.0/24`). | Standard **CIDR notation** (`10.1.1.0/24`). |
| **Implicit Final Rule** | **Implicit `deny ip any any`** (unlogged unless explicit rule added). | **Implicit `deny ip any any`** at end of interface ACL. | **Implicit `Deny` (`policyid 0`)** (logging disabled by default until toggled). | **IMPLICIT `ACCEPT` (PERMIT ALL)!** Every chain permits unmatched packets unless an explicit final `action=drop` rule exists. |
| **Stateful Inspection** | Stateless ACLs unless paired with Zone-Based Firewall (`ZBFW`). Return TCP/UDP traffic must be permitted or `established` used. | Stateful by default (`adaptive security algorithm`). | Stateful by default (session table matches return traffic). | Stateful when `connection-state=established,related` is placed at top of chain. |
| **Safe Rollback / Anti-Lockout Mechanism** | `reload in 10` (or `configure terminal revert timer 10` with archive config). | `reload in 10` before applying risky changes. | `config system global -> set cfg-save revert -> set cfg-revert-timeout 600`. | Press **`Ctrl + X`** in CLI (or click **Safe Mode** button in WinBox) before editing firewall rules. |

---

## 2. Mathematical Rule Conflict Classification (First-Match Semantics)

Given two rules $R_i$ and $R_j$ in the same ACL/chain where $i < j$ ($R_i$ is evaluated before $R_j$):

1. **Exact Duplicate (`REDUNDANT_EXACT`):**
   - $\text{Scope}(R_i) = \text{Scope}(R_j)$ and $\text{Action}(R_i) = \text{Action}(R_j)$.
   - *Impact:* Wastes TCAM/CPU cycles and clutters audit reviews. Remove $R_j$.
2. **Subset Redundancy (`REDUNDANT_SUBSET`):**
   - $\text{Scope}(R_j) \subset \text{Scope}(R_i)$ and $\text{Action}(R_i) = \text{Action}(R_j)$.
   - *Impact:* $R_j$ never records hits (`hitcnt=0`) because $R_i$ already permits/denies the traffic. Remove $R_j$ (or narrow $R_i$ if $R_i$ was unintended).
3. **Shadowed Security Bypass (`SHADOWED_PERMIT_BEFORE_DENY` — CRITICAL):**
   - $\text{Scope}(R_j) \subseteq \text{Scope}(R_i)$, $\text{Action}(R_i) = \text{Permit}$, and $\text{Action}(R_j) = \text{Deny}$.
   - *Impact:* A specific block rule $R_j$ (e.g., `deny tcp any host 10.10.1.50 eq 3389`) was appended *below* a broader permit rule $R_i$ (e.g., `permit ip any 10.10.1.0/24`). Attackers can still reach `10.10.1.50:3389`.
   - *Fix:* Move $R_j$ to a sequence number **above** $R_i$.
4. **Shadowed Dead Permit (`SHADOWED_DENY_BEFORE_PERMIT` — HIGH):**
   - $\text{Scope}(R_j) \subseteq \text{Scope}(R_i)$, $\text{Action}(R_i) = \text{Deny}$, and $\text{Action}(R_j) = \text{Permit}$.
   - *Impact:* An engineer added $R_j$ to open a port for an application, but an earlier summary `deny` block $R_i$ drops the packet first.
   - *Fix:* Move $R_j$ **above** $R_i$ after validating security approval.
5. **Correlation / Partial Overlap (`OVERLAPPING_CONFLICT`):**
   - $\text{Scope}(R_i) \cap \text{Scope}(R_j) \neq \emptyset$, neither is a full subset of the other, and $\text{Action}(R_i) \neq \text{Action}(R_j)$.
   - *Impact:* Order-dependent behavior on the intersection subnet/port. Document and explicitly scope both rules.

---

## 3. Vendor-Specific CLI Remediation & Reordering Cheatsheet

### A. Cisco IOS / IOS-XE Named Extended ACL
```ios
! 1. Arm safety rollback timer (10 minutes)
reload in 10 "Firewall ACL maintenance - auto-rollback safety"

! 2. Resequence ACL to create room between lines (start at 10, increment by 10)
ip access-list resequence WAN-INBOUND 10 10

! 3. Insert specific deny BEFORE broad permit (e.g. sequence 15 before sequence 20)
configure terminal
ip access-list extended WAN-INBOUND
 no 90
 15 deny tcp any host 10.20.1.15 eq 3389 log
exit

! 4. Verify connectivity & cancel reload timer
do show ip access-lists WAN-INBOUND
reload cancel
write memory
```

### B. Cisco ASA (`access-list`)
```asa
! Insert specific rule at line 2 and remove shadowed line 18
configure terminal
access-list OUTSIDE_IN line 2 extended deny tcp any host 172.16.10.25 eq 445 log
no access-list OUTSIDE_IN line 19 extended deny tcp any host 172.16.10.25 eq 445
write memory
```

### C. Fortinet FortiGate (`FortiOS`)
```fortios
# Move specific block policy ID 42 above broad accept policy ID 12
config firewall policy
    move 42 before 12
    # Delete confirmed redundant/zero-hit policy ID 88
    delete 88
end
```

### D. MikroTik RouterOS (v6 / v7)
```routeros
# Press Ctrl+X to enter <SAFE MODE> first!
# 1. Ensure established/related fast-path is at top of input/forward chains
/ip firewall filter
add chain=input connection-state=established,related,untracked action=accept comment="Accept established/related" place-before=0
add chain=input connection-state=invalid action=drop comment="Drop invalid" place-before=1

# 2. Move shadowed rule #8 before broad rule #3
/ip firewall filter move numbers=8 destination=3

# 3. Add mandatory final drop rule on WAN input chain (after permitting LAN/mgmt)
/ip firewall filter add chain=input in-interface-list=WAN action=drop log=yes log-prefix="WAN-INPUT-DROP" comment="Explicit final WAN input drop"
```
