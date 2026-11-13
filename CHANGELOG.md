# Changelog

All notable changes to `firewall-acl-auditor` are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-11-13

First versioned release. The skill itself was already in use; this release establishes
the version baseline and closes a set of library-wide consistency gaps.

### Added
- Shared residual sanitization pass (`scripts/sanitizer.py`), vendored identically
  across every skill in the library, enforcing one credential and PII redaction floor
  rather than 13 independently drifting implementations.
- Sanitization conformance suite (`tests/sanitizer_conformance_test.py`) asserting the
  same adversarial corpus and the same preserved-placeholder set in every skill.
- Continuous integration (`.github/workflows/tests.yml`): every test suite across
  Python 3.9-3.13 on Linux, macOS, and Windows, plus a stdlib-only dependency check and
  a skill-contract check that fails on missing frontmatter or unreferenced bundled files.
- `SECURITY.md` with the read-only/no-egress posture, checksum verification guidance,
  and a private vulnerability reporting path.
- `CONTRIBUTING.md` documenting the library's non-negotiable rules.
- Frontmatter `license`, `version`, and `metadata` fields.

### Changed
- `SKILL.md` now references every bundled script, reference, and asset. Files that an
  agent could never load are either wired in or removed.
- Descriptions carry an explicit "Use when ..." trigger clause so skill selection is
  driven by the situations the skill actually handles.

### Fixed
- Sanitization gaps: public IPv4, compressed IPv6, emails, JWTs, bearer tokens, cloud
  provider keys, connection-string passwords, private key blocks, SSNs, and payment card
  numbers are now redacted consistently, not per-skill.

[Unreleased]: https://github.com/ToritsejuBoyo/firewall-acl-auditor/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/ToritsejuBoyo/firewall-acl-auditor/releases/tag/v1.0.0
