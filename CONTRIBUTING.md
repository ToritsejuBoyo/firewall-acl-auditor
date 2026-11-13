# Contributing to `firewall-acl-auditor`

Thanks for considering a contribution. This skill is part of the
[it-ops-skills](https://github.com/ToritsejuBoyo) library, and it follows a small set
of rules that keep every skill in the library interchangeable and safe to run in
production environments.

## Non-negotiables

These are enforced by CI, so a pull request that breaks one will fail before review.

1. **Standard library only.** No `pip install`, no `requirements.txt`, no
   `pyproject.toml`. If you need to read a `.xlsx`, parse it with `zipfile` and
   `xml.etree` as the existing code does. The library's value is that it runs anywhere
   Python does, with nothing to provision.
2. **Read-only against target systems.** Collectors may read logs, registry keys,
   command output, and API responses. They must not write, delete, restart, install,
   or reconfigure anything. Remediation is *emitted as reviewable text*, never
   executed.
3. **Sanitization is shared, not forked.** `scripts/sanitizer.py` is vendored
   identically across every skill. Do not edit a local copy to loosen it. If a
   redaction class is missing, add it to the canonical module and re-vendor to all
   skills, and add a case to `tests/sanitizer_conformance_test.py`.
4. **Every bundled file must be reachable.** If you add anything to `scripts/`,
   `references/`, or `assets/`, reference it from `SKILL.md`. An unreferenced file is
   never loaded by an agent, so it is dead weight that still costs the reader
   attention. CI fails on orphans.
5. **No emoji in skill output or templates.** Enterprise change tickets and KB
   articles render in systems that mangle them.

## Running the tests

Every file in `tests/` is a self-contained runner that exits non-zero on failure:

```bash
for test in tests/*.py; do python "$test" || echo "FAILED: $test"; done
```

CI runs this across Python 3.9-3.13 on Linux, macOS, and Windows. Please check at
least one platform locally before opening a pull request.

## Adding a diagnostic rule

Rules are deterministic by design: the same input must always produce the same verdict.
That is what makes the output defensible in a post-incident review.

1. Add the detection logic to the engine in `scripts/`.
2. Add a fixture to `tests/fixtures/` that triggers it — synthetic data only, never a
   real capture from a real environment.
3. Add a test asserting both the verdict *and* that no raw identifier leaks into the
   sanitized output.
4. Document the rule in the relevant file under `references/` so a human can audit the
   reasoning without reading the code.

## Changing `SKILL.md`

`SKILL.md` is the agent-facing contract, and it is read top to bottom by a model with
limited context. Keep it instructional rather than discursive: say what to run, in what
order, and how to interpret the result. Put deep background in `references/` and link
to it, so it loads only when it is needed.

If you document a CLI flag, verify it exists. A documented flag that the script does
not implement is a bug — it sends the agent down a path that fails.

## Commit and pull request style

- One logical change per pull request.
- Conventional commit prefixes (`feat:`, `fix:`, `test:`, `docs:`, `refactor:`).
- Say what changed and why in the body. "Why" is the part reviewers cannot reconstruct.
- Note explicitly if you changed sanitization behaviour, since that affects every
  skill in the library.

## Reporting bugs

Open an issue with the input that triggered it (sanitized), the output you got, and the
output you expected. For anything security-related, follow [SECURITY.md](SECURITY.md)
instead and report privately.
