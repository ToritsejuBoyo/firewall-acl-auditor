#!/usr/bin/env python3
"""
Shared residual sanitization pass for the it-ops-skills library.

This module is VENDORED IDENTICALLY into every skill under `scripts/sanitizer.py`.
Do not fork it per-skill: edit the canonical copy and re-vendor, so that every skill
that advertises "zero PII leakage" enforces exactly the same guarantee.

Purpose
-------
Each skill ships its own domain-aware sanitizer (masking VM names, hostnames, pod
namespaces, and so on). Those are intentionally domain-specific. This module is the
*residual* pass that runs last and catches the credential and PII classes that must
never leave an operator's machine regardless of which skill is running.

Contract
--------
- Pure Python standard library (Rule 3).
- Deterministic: identical input always yields identical output.
- Idempotent: residual_scrub(residual_scrub(x)) == residual_scrub(x).
- Non-destructive to placeholders: RFC 5737 / RFC 3849 documentation addresses,
  `example.com` / `example.internal` names, and existing [REDACTED-*] tokens are
  left untouched so a skill's own masking survives this pass.
"""

import re
from typing import Dict, FrozenSet, List, Match, Optional, Pattern, Tuple

__all__ = ["residual_scrub", "scrub_report", "REDACTION_CLASSES"]

# Placeholders that must survive untouched. Swapped out before any substitution so a
# second pass cannot corrupt the output of the first.
#
# Deliberately NOT listed here: existing [REDACTED-*] tokens. Stashing those behind a
# sentinel would hide them from the `(?!\[REDACTED)` guards in the credential rules,
# which is how an already-redacted value could be rewritten a second time (for example
# a skill's own [REDACTED-SECRET] being re-matched as a connection-string password).
# Those tokens are protected by the in-rule lookaheads instead.
# Each entry pairs a pattern with the cheap lowercase markers that must be present for
# it to have any chance of matching. Without these gates, the address-shaped patterns
# scan every document in full - and the e-mail pattern in particular backtracks
# polynomially over long hyphen/dot runs such as a 15,000-character node hostname.
_PRESERVE_RULES: Tuple[Tuple[Pattern, Tuple[str, ...]], ...] = (
    (re.compile(r"\b192\.0\.2\.\d{1,3}\b"), ("192.0.2.",)),
    (re.compile(r"\b198\.51\.100\.\d{1,3}\b"), ("198.51.100.",)),
    (re.compile(r"\b203\.0\.113\.\d{1,3}\b"), ("203.0.113.",)),
    (re.compile(r"\b2001:0?db8:[0-9a-fA-F:]*"), ("2001:db8", "2001:0db8")),
    # Library-wide synthetic GUID convention: every skill's own sanitizer emits
    # placeholders whose first two groups are zeroed (00000000-0000-4000-a000-...,
    # 00000000-0000-0000-0000-redactedNNNN, and so on). These are already masked,
    # so re-redacting them would corrupt a skill's output on a second pass.
    (
        re.compile(r"\b00000000-0000-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9A-Za-z]{1,12}\b"),
        ("00000000-0000-",),
    ),
    # QEMU/libvirt reserved OUI, used as the library's synthetic MAC placeholder.
    (re.compile(r"\b52:54:00(?::[0-9A-Fa-f]{2}){3}\b"), ("52:54:00",)),
    # RFC 7042 documentation MAC range (00:00:5E:00:53:xx), also used as a
    # placeholder, in colon and hyphen notation.
    (
        re.compile(r"\b00[:-]00[:-]5[Ee][:-]00[:-]53[:-][0-9A-Fa-f]{2}\b"),
        ("00:00:5e", "00-00-5e"),
    ),
    # Addresses whose domain sits under a reserved, non-routable TLD, or under an
    # RFC 2606 documentation domain, are already-masked placeholders rather than real
    # contact details. `.local` (RFC 6762) and `.internal` (ICANN-reserved) can never
    # be public mail domains, so nothing reachable is preserved by this rule.
    #
    # This is what keeps a skill's own placeholders intact: admin@corp.example.internal,
    # mock-user-01@synthetic-test.local, and the synthetic Kerberos realm
    # SERVER-01.contoso.local@CONTOSO.LOCAL. A real address such as
    # admin.user@contoso.com still falls through to the email redaction rule.
    #
    # The local part is bounded to 64 characters (the RFC 5321 maximum) and each domain
    # label to 63: unbounded quantifiers here backtrack polynomially over long hyphen
    # runs, which is a denial-of-service vector on hostile log input.
    #
    # The leading (?<!:) is load-bearing. Without it, the password in a URI such as
    # mongodb://svcacct:P4sswordHere@db01.internal:27017 parses as an address on a
    # reserved TLD, gets preserved, and is thereby shielded from the connection-string
    # rule - turning a protective rule into a credential leak. A `mailto:`-prefixed
    # placeholder is simply redacted instead, which errs in the safe direction.
    (
        re.compile(
            r"(?<!:)\b[A-Za-z0-9._%+\-]{1,64}@(?:[A-Za-z0-9\-]{1,63}\.){0,8}"
            r"(?:example\.(?:com|org|net)"
            r"|local|internal|invalid|test|localhost|example)\b",
            re.IGNORECASE,
        ),
        ("@",),
    ),
)

_SENTINEL = "\x00P{0}\x00"


def _protect(text: str) -> Tuple[str, List[str]]:
    """Swap preserved placeholders out for sentinels so rules cannot rewrite them."""
    stash: List[str] = []
    lowered = text.lower()

    def _stash(match: Match) -> str:
        stash.append(match.group(0))
        return _SENTINEL.format(len(stash) - 1)

    for pattern, markers in _PRESERVE_RULES:
        if not any(marker in lowered for marker in markers):
            continue
        # Same domain-side gate as the email redaction rule: without "@domain.tld"
        # present, the address-shaped preserve pattern cannot match, and scanning for
        # it anyway costs O(n * 64) on long local-part-shaped runs.
        if "@" in markers and not _REGEX_GATES["email"].search(text):
            continue
        text = pattern.sub(_stash, text)
    return text, stash


_SENTINEL_RE = re.compile(r"\x00P(\d+)\x00")


def _restore(text: str, stash: List[str]) -> str:
    """
    Restore every stashed placeholder in a single pass.

    Deliberately not a loop of `str.replace` over the stash: that rescans the whole
    document once per stashed item, which is O(text * stash) and becomes the dominant
    cost on large inputs (a 5,000-line bundle stashes thousands of addresses).

    A rule may legitimately consume a stashed value whole (for example
    `password=192.0.2.10`, where redacting the secret outranks preserving the
    documentation address). Any sentinel left dangling resolves to an empty string, so
    control characters can never reach the output.
    """
    if not stash:
        return _SENTINEL_RE.sub("", text)

    def _pop(match: Match) -> str:
        index = int(match.group(1))
        return stash[index] if index < len(stash) else ""

    return _SENTINEL_RE.sub(_pop, text)


# Ordered most-specific first. Order is load-bearing: credential material must be
# matched before the generic token and email rules can consume parts of it.
_RULES: Tuple[Tuple[str, Pattern, str], ...] = (
    # --- Private keys -------------------------------------------------------
    (
        "private-key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"
            r".*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----",
            re.DOTALL,
        ),
        "[REDACTED-PRIVATE-KEY]",
    ),
    # --- Cloud provider credentials -----------------------------------------
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"), "[REDACTED-AWS-KEY]"),
    # 35+ rather than exactly 35: a fixed length plus \b fails to match whenever a
    # key is longer than the canonical form, which would silently leak it.
    ("gcp-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35,}"), "[REDACTED-GCP-KEY]"),
    ("slack-token", re.compile(r"\bxox[abprs]\-[0-9A-Za-z\-]{10,}\b"), "[REDACTED-SLACK-TOKEN]"),
    ("github-token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "[REDACTED-GITHUB-TOKEN]"),
    # --- Bearer tokens and JWTs ---------------------------------------------
    (
        "jwt",
        re.compile(r"\beyJ[0-9A-Za-z_\-]{6,}\.[0-9A-Za-z_\-]{6,}\.[0-9A-Za-z_\-]{6,}"),
        "[REDACTED-JWT]",
    ),
    (
        "bearer-token",
        re.compile(r"(?i)\b(bearer)\s+(?!\[REDACTED)[0-9A-Za-z._~+/=\-]{12,}"),
        r"\1 [REDACTED-TOKEN]",
    ),
    # --- Connection strings --------------------------------------------------
    (
        "connection-string",
        re.compile(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]+):(?!\[REDACTED)([^\s/@]{3,})@"),
        r"\1:[REDACTED-PASSWORD]@",
    ),
    (
        "shared-access-key",
        re.compile(r"(?i)\b(AccountKey|SharedAccessKey|SharedAccessSignature)=(?!\[REDACTED)([^;\s]{8,})"),
        r"\1=[REDACTED-KEY]",
    ),
    # --- Assigned secrets (key=value / key: value) ---------------------------
    (
        "assigned-secret",
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|client[_\-]?secret|api[_\-]?key|apikey"
            r"|access[_\-]?key|private[_\-]?key|token|auth[_\-]?token|credential"
            r"|connection[_\-]?string|sas[_\-]?token)"
            r"(\s*[:=]\s*)"
            # Refuse values that are already redacted, including quoted ones. Matching
            # `Password = "[REDACTED-SECRET]"` again would strip the quotes and leave
            # syntactically invalid PowerShell/JSON behind.
            r"(?!\[REDACTED)(?!\"\[REDACTED)(?!'\[REDACTED)"
            r"(\"[^\"\n]{3,}\"|'[^'\n]{3,}'|[^\s,;\"'<>\]})]{3,})"
        ),
        r"\1\2[REDACTED-SECRET]",
    ),
    (
        "powershell-secret-param",
        re.compile(
            r"(?i)(\-(?:Password|ClientSecret|ApiKey|Token|Credential)\s+)"
            r"(?!\[REDACTED)(?!\"\[REDACTED)(?!'\[REDACTED)"
            r"(\"[^\"\n]{3,}\"|'[^'\n]{3,}'|[^\s]{3,})"
        ),
        r"\1[REDACTED-SECRET]",
    ),
    # --- Personal identifiers -------------------------------------------------
    (
        # Local part bounded to the RFC 5321 maximum of 64 and the domain to 255.
        # An unbounded `+` here backtracks polynomially across long hyphen or dot runs
        # (an `ip-10-10-10-...ec2.internal` node name, for example), which is a
        # denial-of-service vector on hostile log input rather than a correctness bug.
        "email",
        re.compile(
            r"\b[A-Za-z0-9._%+\-]{1,64}@(?!example\.(?:com|org|net|internal)\b)"
            r"[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}\b"
        ),
        "[REDACTED-EMAIL]",
    ),
    ("us-ssn", re.compile(r"\b(?!000|666|9\d\d)\d{3}\-(?!00)\d{2}\-(?!0000)\d{4}\b"), "[REDACTED-SSN]"),
    (
        "credit-card",
        re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6011)[ \-]?\d{4}[ \-]?\d{4}[ \-]?\d{4}\b"),
        "[REDACTED-PAN]",
    ),
    (
        "e164-phone",
        re.compile(r"(?<![\w.])\+\d{1,3}[ \-]?\(?\d{2,4}\)?[ \-]?\d{3,4}[ \-]?\d{3,4}(?![\w.])"),
        "[REDACTED-PHONE]",
    ),
    # --- Network identifiers --------------------------------------------------
    ("mac-address", re.compile(r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"), "[REDACTED-MAC]"),
    (
        # Deliberately matches only (a) fully-expanded 8-group addresses and
        # (b) addresses containing "::" compression. A looser "2 or more hex
        # groups" pattern would also swallow log timestamps such as 11:24:42,
        # so the group count is load-bearing. Loopback "::1" is preserved, for
        # the same reason 127.0.0.1 is.
        "ipv6",
        re.compile(
            r"(?<![\w:.])(?:"
            r"(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}"
            r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){0,6})?"
            r")(?![\w.])"
        ),
        "[REDACTED-IPV6]",
    ),
    (
        "ipv4",
        re.compile(
            r"(?<![\w.])(?!0\.0\.0\.0(?![\d.]))(?!127\.0\.0\.1(?![\d.]))"
            r"(?!255\.255\.255\.255(?![\d.]))"
            r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\w.])"
        ),
        "[REDACTED-IPV4]",
    ),
    # --- Directory identifiers -------------------------------------------------
    (
        "guid",
        re.compile(
            r"(?<![\w\-])(?!00000000\-0000\-0000\-0000\-000000000000)"
            r"[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}(?![\w\-])"
        ),
        "[REDACTED-GUID]",
    ),
    # --- Control characters that can spoof report rendering --------------------
    ("bidi-control", re.compile(r"[\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]"), ""),
)

REDACTION_CLASSES: Tuple[str, ...] = tuple(name for name, _, _ in _RULES)

# Cheap lowercase substring gates. A rule's regex only runs when at least one of its
# markers is present in the text, which avoids scanning an entire document with a
# pattern that provably cannot match. Rules absent from this map always run.
#
# Every marker must be a strict necessary condition of the regex: if a marker is wrong,
# the rule silently stops firing and a secret leaks. Markers are therefore derived from
# the literal anchors in each pattern.
_PREFILTERS: Dict[str, Tuple[str, ...]] = {
    "private-key": ("private key",),
    "aws-access-key": ("akia", "asia", "abia", "acca"),
    "gcp-api-key": ("aiza",),
    "slack-token": ("xox",),
    "github-token": ("ghp_", "gho_", "ghu_", "ghs_", "ghr_"),
    "jwt": ("eyj",),
    "bearer-token": ("bearer",),
    "connection-string": ("://",),
    "shared-access-key": ("accountkey=", "sharedaccesskey=", "sharedaccesssignature="),
    "assigned-secret": (
        "password", "passwd", "pwd", "secret", "api_key", "api-key", "apikey",
        "access_key", "access-key", "private_key", "private-key", "token",
        "credential", "connection_string", "connection-string", "connectionstring",
        "sas_token", "sas-token",
    ),
    "powershell-secret-param": (
        "-password", "-clientsecret", "-apikey", "-token", "-credential",
    ),
    "email": ("@",),
    "e164-phone": ("+",),
    # mac-address, ipv6, ipv4 and guid deliberately have no substring marker. Their
    # natural markers would be ".", ":" and "-", which appear in almost every line of
    # real diagnostic text and so gate nothing. They use shape gates below instead.
}


# Some rules need a stronger gate than a substring. An address-shaped rule anchored on
# its *local* part must try every position in the document before it can fail, so a
# payload like ("a." * 50000 + "@") costs O(n * 64) for zero matches. Gating on the
# domain side instead is cheap, because the engine can scan for the literal "@" quickly.
#
# Each gate must be a strict necessary condition of its rule: if the gate cannot match,
# the rule provably cannot match either. Getting that wrong silently disables redaction,
# so the conformance suite re-checks every sensitive case against these gates.
_REGEX_GATES: Dict[str, Pattern] = {
    # An address requires "@" followed by a domain with a dot and a TLD. Without that,
    # no amount of local-part text can form one.
    "email": re.compile(r"@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,24}"),
}


# Necessary-condition gates for the rules that have no substring marker. Without these
# the rule must run on every call, which is what makes per-field use expensive: skills
# such as vuln-scan-prioritizer call this pass once per CSV field, thousands of times
# per run, so fixed per-call cost dominates over any document-size effect.
#
# Each is a strict necessary condition, derived from a literal the pattern cannot match
# without:
#   us-ssn      - the pattern contains two literal hyphens between digits
#   credit-card - every brand prefix begins with four consecutive digits
#   bidi-control- the gate is the character class itself
#   ipv4        - every match contains a digit, a dot and a digit
#   ipv6        - every match contains a hex digit followed by a colon
#   mac-address - every match contains two hex digits, a separator, two more
#   guid        - every match begins with eight hex digits and a hyphen
#
# Gates are searched against a lowercased copy, so they only need lowercase hex.
_SHAPE_GATES: Dict[str, str] = {
    "us-ssn": r"\d-\d",
    "credit-card": r"\d{4}",
    "bidi-control": r"[​-‏‪-‮⁦-⁩﻿]",
    "ipv4": r"\d\.\d",
    "ipv6": r"[0-9a-f]:",
    "mac-address": r"[0-9a-f]{2}[:\-][0-9a-f]{2}",
    "guid": r"[0-9a-f]{8}-",
}


def _build_gate(name: str) -> Optional[Pattern]:
    """Compile one rule's necessary condition into a single regex, or None if it has
    no gate (meaning the rule always runs)."""
    alternatives = []
    markers = _PREFILTERS.get(name)
    if markers:
        # One compiled alternation beats N Python-level `in` checks per call; the
        # assigned-secret rule alone has 18 markers.
        alternatives.append("|".join(re.escape(marker) for marker in markers))
    shape = _SHAPE_GATES.get(name)
    if shape:
        alternatives.append(shape)
    if not alternatives:
        return None
    return re.compile("|".join(alternatives))


# Flat tuple of (name, pattern, replacement, marker_gate, strict_gate). Iterated
# directly so the hot loop performs no dict lookups.
_COMPILED_RULES: Tuple[Tuple[str, Pattern, str, Optional[Pattern], Optional[Pattern]], ...] = tuple(
    (name, pattern, replacement, _build_gate(name), _REGEX_GATES.get(name))
    for name, pattern, replacement in _RULES
)

# Union of every rule's necessary condition. If this does not match, no rule can match,
# so the whole pass is skipped after a single scan. This is what makes per-field use
# cheap: most fields are prose with no identifier or credential shape at all.
_ANY_TRIGGER: Pattern = re.compile(
    "|".join(
        gate.pattern for _, _, _, gate, _ in _COMPILED_RULES if gate is not None
    )
)

# Rules with no gate at all would invalidate the _ANY_TRIGGER shortcut, since they must
# run unconditionally. Assert the invariant at import rather than leaking silently.
_UNGATED = tuple(name for name, _, _, gate, _ in _COMPILED_RULES if gate is None)
if _UNGATED:  # pragma: no cover - guards a developer mistake, not runtime input
    raise RuntimeError(
        "sanitizer: rules without a necessary-condition gate would be skipped by the "
        "_ANY_TRIGGER shortcut: {0}".format(", ".join(_UNGATED))
    )


def _rule_applies(name: str, lowered: str, original: Optional[str] = None) -> bool:
    """Kept for conformance tests and external callers; the hot path inlines this."""
    for rule_name, _, _, gate, strict in _COMPILED_RULES:
        if rule_name != name:
            continue
        if gate is not None and not gate.search(lowered):
            return False
        if strict is not None and not strict.search(
            original if original is not None else lowered
        ):
            return False
        return True
    return True


def residual_scrub(text: str, skip: Optional[FrozenSet[str]] = None) -> str:
    """
    Apply the shared residual redaction pass.

    Args:
        text: Input text. Non-strings return an empty string; empty input is returned
              unchanged.
        skip: Optional set of names from REDACTION_CLASSES to leave unapplied. Use
              sparingly, and only where a skill provably needs the raw value (for
              example a routing skill that must preserve IPv4 structure).

    Returns:
        The redacted text. Deterministic and idempotent.
    """
    if not isinstance(text, str) or not text:
        return text if isinstance(text, str) else ""

    # Single-scan shortcut. If nothing in the text satisfies any rule's necessary
    # condition, no rule can match and the pass is a no-op. This keeps per-field callers
    # cheap: most fields are prose with no credential or identifier shape.
    lowered_input = text.lower()
    if not _ANY_TRIGGER.search(lowered_input):
        return text

    active = skip or frozenset()
    protected, stash = _protect(text)

    # Lowered once, not per rule. A substitution only ever removes secret material and
    # inserts [REDACTED-*] tokens, which the credential rules already refuse to re-match
    # via their (?!\[REDACTED) guards. So a marker that disappears mid-pass only ever
    # belonged to a value that has already been redacted.
    lowered = protected.lower() if stash else lowered_input

    for name, pattern, replacement, gate, strict in _COMPILED_RULES:
        if name in active:
            continue
        if gate is not None and not gate.search(lowered):
            continue
        if strict is not None and not strict.search(protected):
            continue
        protected = pattern.sub(replacement, protected)

    return _restore(protected, stash)


def scrub_report(
    text: str, skip: Optional[FrozenSet[str]] = None
) -> Tuple[str, Dict[str, int]]:
    """Return the scrubbed text plus a per-class count of what was redacted."""
    if not isinstance(text, str) or not text:
        return (text if isinstance(text, str) else ""), {}

    active = skip or frozenset()
    protected, stash = _protect(text)
    lowered = protected.lower()
    counts: Dict[str, int] = {}

    for name, pattern, replacement, gate, strict in _COMPILED_RULES:
        if name in active:
            continue
        if gate is not None and not gate.search(lowered):
            continue
        if strict is not None and not strict.search(protected):
            continue
        protected, hits = pattern.subn(replacement, protected)
        if hits:
            counts[name] = hits

    return _restore(protected, stash), counts


if __name__ == "__main__":
    import sys

    cleaned, report = scrub_report(sys.stdin.read())
    sys.stdout.write(cleaned)
    if report:
        sys.stderr.write("\nRedaction summary:\n")
        for key in sorted(report):
            sys.stderr.write("  {0}: {1}\n".format(key, report[key]))
