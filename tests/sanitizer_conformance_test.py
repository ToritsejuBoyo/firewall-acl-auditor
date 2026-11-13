#!/usr/bin/env python3
"""
Shared sanitization conformance suite for the it-ops-skills library.

This file is VENDORED IDENTICALLY into every skill under
`tests/sanitizer_conformance_test.py`. It is the single corpus that makes the
"zero PII leakage" claim testable and identical across all skills: every skill
must redact the same credential and PII classes from the same adversarial input.

Run:  python tests/sanitizer_conformance_test.py
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))

from sanitizer import REDACTION_CLASSES, residual_scrub, scrub_report  # noqa: E402

# (label, raw input, substring that must NOT survive)
MUST_REDACT = [
    ("corporate email", "Escalated by admin.user@contoso.com today", "admin.user@contoso.com"),
    ("upn", "Sign-in for j.doe@fabrikam.co.uk failed", "j.doe@fabrikam.co.uk"),
    ("aws access key", "env AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    ("gcp api key", "key AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r", "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r"),
    ("slack token", "hook xoxb-1234567890-abcdefghijkl", "xoxb-1234567890-abcdefghijkl"),
    ("github pat", "token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"),
    ("jwt", "Auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.dBjftJeZ4CVPmB92K27u", "eyJhbGciOiJIUzI1NiJ9"),
    ("bearer token", "Bearer ya29.a0AfH6SMBx7vKq1234567890abcdef", "ya29.a0AfH6SMBx7vKq1234567890abcdef"),
    ("password assignment", 'password="Sup3rS3cret!2024"', "Sup3rS3cret!2024"),
    ("client secret colon", "client_secret: abc123def456ghi789", "abc123def456ghi789"),
    ("powershell secret param", "-ClientSecret 'Xy9#kLmn01pq'", "Xy9#kLmn01pq"),
    ("connection string", "mongodb://svcacct:P4sswordHere@db01.internal:27017", "P4sswordHere"),
    ("azure account key", "AccountKey=abcdEFGH1234567890abcdEFGH==", "abcdEFGH1234567890abcdEFGH=="),
    # Regression: a URI password followed by a reserved-TLD host used to parse as a
    # preserved internal e-mail address, shielding the credential from redaction.
    ("conn string reserved tld host", "mongodb://svcacct:P4sswordHere@db01.internal:27017", "P4sswordHere"),
    ("conn string local tld host", "postgresql://svc:S3cretPass@db01.corp.local:5432/fin", "S3cretPass"),
    ("private key block", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQ\n-----END RSA PRIVATE KEY-----", "MIIEowIBAAKCAQ"),
    ("public ipv4", "peer established with 8.8.8.8", "8.8.8.8"),
    ("private ipv4", "gateway 10.20.30.40 unreachable", "10.20.30.40"),
    ("mac colon", "adapter 00:1A:2B:3C:4D:5E down", "00:1A:2B:3C:4D:5E"),
    ("mac dash", "adapter 00-1A-2B-3C-4D-5E down", "00-1A-2B-3C-4D-5E"),
    ("ipv6 compressed", "neighbour fe80::1ff:fe23:4567:890a", "fe80::1ff:fe23:4567:890a"),
    ("tenant guid", "tenant 72f988bf-86f1-41af-91ab-2d7cd011db47", "72f988bf-86f1-41af-91ab-2d7cd011db47"),
    ("us ssn", "employee ssn 123-45-6789 on file", "123-45-6789"),
    ("credit card", "card 4111 1111 1111 1111 declined", "4111 1111 1111 1111"),
    ("e164 phone", "callback +1 415 555 0132 requested", "+1 415 555 0132"),
]

# (label, input) - these must survive a scrub byte-for-byte.
MUST_PRESERVE = [
    ("rfc5737 test-net-1", "masked host 192.0.2.10 in report"),
    ("rfc5737 test-net-3", "masked peer 203.0.113.9 in report"),
    ("rfc3849 doc prefix", "masked addr 2001:db8::1 in report"),
    ("example.com domain", "synthetic host-a1b2.corp.example.com retained"),
    ("example.internal domain", "synthetic dc01.corp.example.internal retained"),
    ("existing redaction token", "value [REDACTED-SECRET] already masked"),
    ("ipv4 loopback", "bound to 127.0.0.1 locally"),
    ("ipv6 loopback", "bound to ::1 locally"),
    ("nil guid", "id 00000000-0000-0000-0000-000000000000 is nil"),
    ("synthetic v4 placeholder guid", "tenant 00000000-0000-4000-a000-000000000001 masked"),
    ("synthetic digest placeholder guid", "oid 00000000-0000-0000-0000-redacted1a2b masked"),
    ("synthetic prefixed placeholder guid", "pod 00000000-0000-4000-a000-p000000000002 masked"),
    ("synthetic mac placeholder", "nic 52:54:00:12:34:56 masked"),
    ("rfc7042 doc mac colon", "nic 00:00:5E:00:53:01 masked"),
    ("rfc7042 doc mac hyphen", "nic 00-00-5E-00-53-01 masked"),
    ("doc email subdomain", "owner admin@corp.example.internal retained"),
    ("doc email example.com", "owner user-0000@corp.example.com retained"),
    ("synthetic placeholder email", "actor mock-user-01@synthetic-test.local retained"),
    ("synthetic lab host email", "actor ops@mock-server-01.synthetic-lab.local retained"),
    ("synthetic kerberos realm", "ticket for HTTP/SERVER-01.contoso.local@CONTOSO.LOCAL failed"),
    ("reserved internal tld", "owner svc@corp.acme.internal retained"),
    ("log timestamp", "event at 11:24:42 UTC"),
    ("iso timestamp", "stamp 2026-11-13T11:24:42Z recorded"),
    ("elapsed duration", "elapsed 1:30:00 total"),
    ("windows build", "Version 10.0.19045 build 19045"),
    ("cve id", "CVE-2024-21412 exploited in the wild"),
    ("semver", "agent version 2.14.3 installed"),
]


class SanitizerConformance(unittest.TestCase):
    """Every skill must satisfy this identical contract."""

    def test_all_sensitive_classes_redacted(self) -> None:
        for label, raw, secret in MUST_REDACT:
            with self.subTest(case=label):
                out = residual_scrub(raw)
                self.assertNotIn(
                    secret, out, "{0}: secret survived scrub -> {1}".format(label, out)
                )
                self.assertIn("[REDACTED-", out, "{0}: no redaction token emitted".format(label))

    def test_placeholders_and_benign_values_preserved(self) -> None:
        for label, raw in MUST_PRESERVE:
            with self.subTest(case=label):
                self.assertEqual(
                    raw, residual_scrub(raw), "{0}: benign value was mangled".format(label)
                )

    def test_idempotent(self) -> None:
        for label, raw, _ in MUST_REDACT:
            with self.subTest(case=label):
                once = residual_scrub(raw)
                self.assertEqual(once, residual_scrub(once), "{0}: not idempotent".format(label))

    def test_deterministic_across_calls(self) -> None:
        corpus = "\n".join(raw for _, raw, _ in MUST_REDACT)
        self.assertEqual(residual_scrub(corpus), residual_scrub(corpus))

    def test_empty_and_non_string_inputs(self) -> None:
        self.assertEqual("", residual_scrub(""))
        self.assertEqual("", residual_scrub(None))  # type: ignore[arg-type]
        self.assertEqual("", residual_scrub(12345))  # type: ignore[arg-type]
        self.assertEqual("", residual_scrub([]))  # type: ignore[arg-type]

    def test_skip_parameter_honoured(self) -> None:
        raw = "gateway 10.20.30.40 unreachable"
        self.assertIn("[REDACTED-IPV4]", residual_scrub(raw))
        self.assertIn("10.20.30.40", residual_scrub(raw, skip=frozenset({"ipv4"})))

    def test_scrub_report_counts(self) -> None:
        raw = "a@contoso.com and b@fabrikam.com from 10.0.0.1"
        cleaned, counts = scrub_report(raw)
        self.assertEqual(2, counts.get("email"))
        self.assertEqual(1, counts.get("ipv4"))
        self.assertNotIn("contoso.com", cleaned)

    def test_multiline_mixed_payload(self) -> None:
        raw = (
            "User admin@contoso.com from 203.0.113.9 via 8.8.8.8\n"
            "password=hunter2abc tenant 72f988bf-86f1-41af-91ab-2d7cd011db47\n"
            "nic 00:1A:2B:3C:4D:5E masked host 192.0.2.10\n"
        )
        out = residual_scrub(raw)
        for leaked in ("admin@contoso.com", "8.8.8.8", "hunter2abc", "00:1A:2B:3C:4D:5E"):
            self.assertNotIn(leaked, out)
        self.assertIn("192.0.2.10", out)
        self.assertIn("203.0.113.9", out)

    def test_redaction_class_registry_is_stable(self) -> None:
        # Guards against a skill silently shipping a forked, weaker copy.
        required = {
            "private-key", "aws-access-key", "gcp-api-key", "slack-token",
            "github-token", "jwt", "bearer-token", "connection-string",
            "shared-access-key", "assigned-secret", "powershell-secret-param",
            "email", "us-ssn", "credit-card", "e164-phone", "mac-address",
            "ipv6", "ipv4", "guid", "bidi-control",
        }
        self.assertTrue(
            required.issubset(set(REDACTION_CLASSES)),
            "missing classes: {0}".format(sorted(required - set(REDACTION_CLASSES))),
        )

    def test_existing_redaction_tokens_are_not_rewritten(self) -> None:
        # Regression: a skill's own [REDACTED-*] token must not be re-matched by a
        # later rule. Partial upstream redaction of a password containing "@" used to
        # leave a token that this pass then rewrote, changing the skill's output.
        raw = (
            "Failed connecting to postgresql://svc_user:[REDACTED-SECRET]"
            "@ssw0rd!#%&*=99@198.51.100.11:5432/finance_db"
        )
        out = residual_scrub(raw)
        self.assertIn("[REDACTED-SECRET]", out)
        self.assertNotIn("[REDACTED-PASSWORD]", out)

    def test_quoting_of_already_redacted_values_is_preserved(self) -> None:
        # Regression: re-matching an already-redacted *quoted* value stripped its
        # quotes, leaving syntactically invalid PowerShell/JSON behind.
        for raw in (
            '$cred = @{ Password = "[REDACTED-SECRET]"; User = "x" }',
            "$secret = '[REDACTED-SECRET]'",
            'client_secret: "[REDACTED-SECRET]"',
            '-ClientSecret "[REDACTED-SECRET]"',
            '{"api_key": "[REDACTED-SECRET]"}',
        ):
            with self.subTest(case=raw):
                self.assertEqual(
                    raw,
                    residual_scrub(raw),
                    "quoting of an already-redacted value was altered",
                )

    def test_no_sentinel_characters_leak(self) -> None:
        for raw in (
            "password=192.0.2.10",
            "secret: 00000000-0000-4000-a000-000000000001",
            "token=52:54:00:12:34:56",
            "api_key: user@example.com",
        ):
            with self.subTest(case=raw):
                out = residual_scrub(raw)
                self.assertNotIn("\x00", out, "sentinel leaked into output: {0}".format(out))

    def test_prefilters_are_case_insensitive(self) -> None:
        # The rule prefilters gate on lowercase markers. If the gate were applied to the
        # raw text instead of a lowered copy, an upper-case secret would silently skip
        # its rule and leak.
        #
        # Only keyword-driven rules are checked here. Rules anchored on a literal
        # case-sensitive prefix (AKIA, AIza, xoxb, ghp_, eyJ) are intentionally
        # case-sensitive: an upper-cased variant is not a valid credential of that type,
        # so redacting it is not required.
        cases = [
            ("upper password", 'PASSWORD="Sup3rS3cret!2024"', "Sup3rS3cret!2024"),
            ("mixed password", 'PassWord: Sup3rS3cret!2024', "Sup3rS3cret!2024"),
            ("upper bearer", "BEARER ya29.a0AfH6SMBx7vKq1234567890abcdef", "ya29.a0AfH6SMBx7vKq1234567890abcdef"),
            ("upper account key", "ACCOUNTKEY=abcdEFGH1234567890abcdEFGH==", "abcdEFGH1234567890abcdEFGH=="),
            ("upper ps param", "-CLIENTSECRET 'Xy9#kLmn01pq'", "Xy9#kLmn01pq"),
            ("mixed client secret", "Client_Secret: abc123def456ghi789", "abc123def456ghi789"),
            ("upper connection string", "POSTGRESQL://svc_user:P4sswordHere@db01:5432", "P4sswordHere"),
        ]
        for label, raw, secret in cases:
            with self.subTest(case=label):
                self.assertNotIn(
                    secret,
                    residual_scrub(raw),
                    "{0}: secret survived scrub".format(label),
                )

    def test_prefilter_gate_does_not_suppress_any_rule(self) -> None:
        # Guards the performance optimisation: a wrong marker makes a rule stop firing
        # without any error. Each sensitive case must still redact when presented alone.
        for label, raw, secret in MUST_REDACT:
            with self.subTest(case=label):
                self.assertNotIn(secret, residual_scrub(raw), "{0} leaked".format(label))

    def test_redos_resilience_on_hostile_input(self) -> None:
        # Hostile diagnostic input is normal here: node names, log lines and config
        # dumps contain very long hyphen and dot runs. Every pattern must stay linear
        # enough that an unbounded quantifier cannot be used as a DoS vector.
        hostile = [
            ("ec2 node name", "ip-" + ("10-" * 5000) + "ec2.internal"),
            ("jwt prefix flood", "eyJhbGciOi" + ("A" * 20000)),
            ("at-sign flood", ("a@" * 10000) + "b"),
            # Local-part-shaped run with a trailing bare "@" and no domain: the email
            # rule must be gated on the domain side, or it tries every position.
            ("dangling at", ("a." * 50000) + "@"),
            ("local part flood no at", "a." * 50000),
            ("dotted flood", ("10." * 10000) + "1"),
            ("colon flood", ("ab:" * 10000) + "cd"),
            ("hyphen guid flood", ("0000-" * 5000) + "abcd"),
            ("keyword flood", ("password=" * 5000)),
            ("scheme flood", ("://a:b@" * 5000)),
        ]
        for label, payload in hostile:
            with self.subTest(case=label):
                start = time.perf_counter()
                residual_scrub(payload)
                elapsed = time.perf_counter() - start
                self.assertLess(
                    elapsed,
                    0.35,
                    "{0}: {1} chars took {2:.3f}s - possible polynomial "
                    "backtracking".format(label, len(payload), elapsed),
                )

    def test_scrub_report_text_matches_residual_scrub(self) -> None:
        # scrub_report stays sequential so it can count per class; its text output must
        # still agree with the fused fast path.
        for _, raw, _ in MUST_REDACT:
            with self.subTest(case=raw[:50]):
                self.assertEqual(residual_scrub(raw), scrub_report(raw)[0])

    def test_no_bidi_control_characters_survive(self) -> None:
        raw = "host‮evil​.com"
        out = residual_scrub(raw)
        for ch in ("‮", "​"):
            self.assertNotIn(ch, out)


if __name__ == "__main__":
    unittest.main(verbosity=2)
