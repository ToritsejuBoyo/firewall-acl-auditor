# Security Policy

## Scope and design posture

`firewall-acl-auditor` is an Agent Skill: a `SKILL.md` instruction set plus local diagnostic
scripts. It is built to the following guarantees, and a breach of any of them is a
security bug worth reporting.

- **Read-only collection.** The bundled collectors gather diagnostic state. They do
  not modify configuration, write to target systems, install software, or change
  service state. Remediation commands are *emitted as text for a human to review and
  run*, never executed by this skill.
- **No third-party dependencies.** Everything runs on the Python standard library (and
  built-in shell utilities). There is no package install step, so there is no
  dependency supply chain to compromise.
- **No network egress.** The scripts do not phone home, upload telemetry, or contact
  any remote endpoint. Output is written to stdout or a local file you choose.
- **Client-side sanitization.** Credential and PII redaction happens locally, before
  output is produced, so sensitive values are removed before anything is shared with
  an AI model or pasted into a ticket. The shared contract lives in
  [`scripts/sanitizer.py`](scripts/sanitizer.py) and is enforced by
  [`tests/sanitizer_conformance_test.py`](tests/sanitizer_conformance_test.py).

## Verifying what you run

Do not pipe remote scripts into a shell or `iex`. Pin to an immutable commit, verify
the checksum, then execute:

```bash
# Linux / macOS
curl -fsSL -o collector.sh \
  "https://raw.githubusercontent.com/ToritsejuBoyo/firewall-acl-auditor/<commit-sha>/scripts/<collector>"
shasum -a 256 collector.sh   # compare against the published checksum
bash ./collector.sh
```

```powershell
# Windows
$Dest = Join-Path $env:TEMP 'collector.ps1'
Invoke-WebRequest -UseBasicParsing -OutFile $Dest `
  -Uri "https://raw.githubusercontent.com/ToritsejuBoyo/firewall-acl-auditor/<commit-sha>/scripts/<collector>"
(Get-FileHash -Path $Dest -Algorithm SHA256).Hash   # compare before running
```

Every script in `scripts/` is plain text and intended to be read before it is run.
Review is encouraged, especially before running anything with elevated privileges.

## Reporting a vulnerability

Please **do not** open a public issue for a security problem.

Report privately via GitHub's [private vulnerability
reporting](https://github.com/ToritsejuBoyo/firewall-acl-auditor/security/advisories/new) on this
repository. Include:

- what the issue is and which file or instruction it affects,
- how to reproduce it (a minimal input bundle is ideal — sanitized, please),
- the impact you believe it has.

You can expect an acknowledgement within 7 days and an assessment within 30 days.

## What counts as a vulnerability here

In scope:

- sensitive data (credentials, tokens, keys, PII) surviving sanitization and reaching
  output;
- a collector or script that writes to, or changes state on, a target system;
- command injection or path traversal through crafted input (a malicious log line,
  scan export, or ticket note);
- instructions in `SKILL.md` that would lead an agent to run a destructive or
  privilege-escalating command;
- denial of service through a crafted input that is plausible in real operations.

Out of scope:

- the remediation commands this skill *recommends* being dangerous when run without
  review — that is the operator's decision, and the output says so;
- findings that require an attacker to already control the machine running the skill;
- results from running the skill against systems you are not authorized to assess.

## Operator responsibilities

Run this skill only against systems you are authorized to diagnose. Review sanitized
output before sharing it outside your organization: sanitization is thorough and
tested, but no redaction is a substitute for reading what you are about to paste.
