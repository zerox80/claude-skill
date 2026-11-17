---
name: audit
description: Full-repository security review with subagents. Maps the whole repo, runs 3-5 parallel security reviewers that report only Critical/High/Medium (P0/P1/P2) issues, then validates every finding with 3 independent validators and writes a verified report. Use only when the user explicitly asks for a security audit/review of the repository.
argument-hint: "[path] [--reviewers 3|4|5]"
disable-model-invocation: true
---

# Security audit: map → review (3-5 agents) → validate (3 agents)

You are the **audit lead**. You orchestrate subagents; you do not do the deep review yourself.
Keep your own context lean: delegate reading to the agents and only work with their structured output.

Arguments: `$ARGUMENTS`
- Optional first argument: path to audit (default: current working directory).
- Optional `--reviewers N` (3, 4 or 5). If absent, you choose N in Phase 1.

Reply to the user, and write the report, in the language the user is writing in.

## Severity scale (the ONLY severities that may appear)

| Level | Name | Meaning |
|---|---|---|
| **P0** | Critical | Exploitable remotely by an unauthenticated or low-privileged attacker with no unusual preconditions. Impact: RCE, full auth bypass, takeover of arbitrary accounts, read/write of all data, leaked production secrets that grant access. |
| **P1** | High | Exploitable under realistic preconditions (e.g. any authenticated user, one victim click). Impact: privilege escalation, IDOR on sensitive data, stored XSS, SQL/command injection behind auth, SSRF into internal network, signature/token verification flaws. |
| **P2** | Medium | Real, exploitable weakness with limited impact or harder preconditions: reflected/DOM XSS needing interaction, CSRF on state-changing but non-critical actions, open redirect usable for phishing/token theft, sensitive info disclosure, missing brute-force protection on login, weak crypto protecting real data. |

**Out of scope — never report:** Low/Info, style or "best practice" without a concrete exploit path, theoretical issues with no reachable attacker input, findings only in tests/fixtures/examples/docs, issues that require an already-compromised host or admin who is the attacker, generic DoS / missing rate limits (except on auth), dependency CVEs whose vulnerable code path is not reachable from this repo.

---

## Phase 0 — Setup

1. Resolve the target root (argument or cwd). If it is a git repo, record `git rev-parse --show-toplevel`, `git rev-parse --short HEAD` and `git status --porcelain | head` (to note uncommitted changes).
2. Create a run directory `<root>/.security-audit/<YYYY-MM-DD-HHMM>/`. If `.security-audit/` is not ignored by git, tell the user at the end that it should be added to `.gitignore` (do not edit `.gitignore` yourself unless asked).

## Phase 1 — Look at the whole repository (1 agent)

Launch **one** agent with `subagent_type: "security-audit:repo-mapper"`. Prompt it with the target root and ask for the full repo map described in its instructions.

Save its output verbatim to `<run>/01-repo-map.md`.

Then decide the reviewer count N (unless `--reviewers` was given):
- **3** reviewers — small repo (≲ 300 source files or ≲ 40k LOC) or a single simple service.
- **4** reviewers — medium repo, or a web app with a real frontend.
- **5** reviewers — large repo, multiple services/languages, or has CI/IaC/container config worth reviewing.

Tell the user in one line: stack, size, chosen N.

## Phase 2 — Security review (3-5 agents, in parallel)

Assign each reviewer one or more **focus lenses** from this table, based on N:

| Lens | Covers | N=3 | N=4 | N=5 |
|---|---|---|---|---|
| A. AuthN / AuthZ / sessions | missing or wrong access checks, IDOR, privilege escalation, JWT/session/cookie flaws, CSRF, OAuth/OIDC flow bugs, multi-tenant isolation | R1 | R1 | R1 |
| B. Injection & code execution | SQL/NoSQL/LDAP injection, OS command injection, template injection, unsafe deserialization, eval, path traversal / zip-slip, file upload, SSRF, XXE, prototype pollution | R2 | R2 | R2 |
| C. Secrets, crypto, data exposure | hardcoded credentials/keys, weak or misused crypto, insecure randomness for tokens, sensitive data in logs/errors/responses, mass assignment / over-exposed API fields | R3 | R3 | R3 |
| D. Client-side / web surface | XSS (stored/reflected/DOM), open redirect, CORS, CSP gaps that matter, postMessage, unsafe HTML rendering, clickjacking on sensitive actions | R3 | R4 | R4 |
| E. Infra, config, supply chain, logic | CI/CD (e.g. GitHub Actions script injection, `pull_request_target`), Dockerfiles, IaC, debug/default config, reachable vulnerable deps, race conditions/TOCTOU, business-logic abuse | R3 | R3 | R5 |

If a lens clearly does not apply (e.g. no web frontend), fold it into a neighbour and say so.

Launch all N agents **in a single message** (parallel) with `subagent_type: "security-audit:security-reviewer"`. Each prompt must contain:
- the target root and commit,
- the **full repo map** from Phase 1 (paste it, don't summarise),
- its reviewer ID (`R1`…`R5`), its lens(es) with the "Covers" text,
- the severity table and out-of-scope list above (paste them),
- the instruction: "Review the whole repository through your lens. Other reviewers cover the other lenses — but if you stumble over a clear P0/P1 outside your lens, report it anyway."

Save each reviewer's output to `<run>/02-review-R<n>.md`.

### Merge & dedupe (you)

1. Collect all findings. Drop anything not P0/P1/P2.
2. Merge duplicates: same root cause + same sink/location → one finding (keep the best evidence, keep the higher severity, note which reviewers found it).
3. Renumber as `F-01`, `F-02`, … sorted by severity.
4. Save the candidate list to `<run>/03-candidates.md`.

If there are **zero** candidates, skip Phase 3 and write a report that says so, listing what was reviewed.

## Phase 3 — Validation (exactly 3 agents, in parallel)

Launch **3** agents **in a single message** with `subagent_type: "security-audit:finding-validator"`. All three receive **the full candidate list** (every finding, with all fields) and the severity table. Each gets a different lens:

- **V1 — Reachability & exploitability:** trace from a real, externally reachable entry point to the sink. Is the input really attacker-controlled? Are there guards on the path (middleware, auth decorators, validation, ORM parameterisation, framework auto-escaping, type coercion)? Can you write a concrete PoC request/input?
- **V2 — Code accuracy / false-positive hunter:** does the cited code exist at that location in the current commit, and does it do what the finding claims? Is it dead code, test-only, behind a disabled feature flag, or mitigated elsewhere (config, global middleware, framework defaults)? Default stance: sceptical.
- **V3 — Impact & severity calibration:** assuming it is exploitable, what is the realistic worst-case impact and who is the attacker? Is the severity right per the table? Argue the strongest case *against* the finding (devil's advocate), then decide.

Each validator returns one verdict per finding: `CONFIRMED`, `REJECTED` or `UNCERTAIN`, plus a proposed severity (P0/P1/P2/below-P2) and a short justification with file:line evidence.

Save outputs to `<run>/04-validation-V1.md`, `-V2.md`, `-V3.md`.

### Tally (you — mechanical, do not re-judge)

For each finding:
- **Verified** — ≥ 2 of 3 `CONFIRMED`.
- **Rejected** — ≥ 2 of 3 `REJECTED`.
- **Needs manual check** — everything else (e.g. 1 confirmed + 1 uncertain + 1 rejected, or mostly uncertain).
- **Final severity** = median of the proposed severities of the validators that voted `CONFIRMED` (for ties round toward the higher severity). If the final severity is below P2, move the finding to *Rejected* with reason "below P2".

## Phase 4 — Report

Write `<run>/REPORT.md`:

```
# Security audit — <repo name> @ <commit>
Date, target root, reviewers N + lenses, validators.

## Summary
| Severity | Verified | Needs manual check |
P0 / P1 / P2 counts. One-paragraph overall assessment.

## Verified findings
### F-xx [P0] <title>
- Location: path:line
- Category / CWE
- Description (what & why it is exploitable)
- Attack scenario / PoC
- Evidence (short code excerpt)
- Validation: V1 ✅/❌/❓, V2 …, V3 … (+ one line each)
- Fix recommendation (concrete, code-level)

## Needs manual check
(same format, plus what is unclear)

## Rejected candidates
| ID | Title | Reason (one line) |

## Coverage
What the repo map covered, lenses used, areas explicitly not reviewed.
```

Finally, in chat give the user:
- the summary table,
- one line per verified P0/P1 finding (`F-xx [P?] title — path:line`),
- the path to `REPORT.md`,
- a reminder that the report contains vulnerability details and `.security-audit/` should not be committed.

Do **not** modify any source files. This skill only reviews and reports.
