---
name: audit
description: Full-repository security review with subagents. Maps the whole repo, runs 10 security reviewers with 10 focus lenses (max. 5 at the same time) that report only Critical/High/Medium (P0/P1/P2) issues, then validates every finding with 3 independent validators and writes a verified report. Use only when the user explicitly asks for a security audit/review of the repository.
argument-hint: "[path] [--reviewers 3-10]"
disable-model-invocation: true
---

# Security audit: map (1) → review (10 agents, 10 lenses) → validate (3), never more than 5 running at once

You are the **audit lead**. You orchestrate subagents; you do not do the deep review yourself.
Keep your own context lean: delegate reading to the agents and only work with their structured output.

Arguments: `$ARGUMENTS`
- Optional first argument: path to audit (default: current working directory).
- Optional `--reviewers N` (3 to 10). If absent, **N = 10**: one reviewer per lens (table in Phase 2). With N < 10 merge neighbouring lenses evenly (e.g. N=5: A+B, C+D, E+F, G, H+I+J).

**Concurrency limit (hard rule):** never have more than **5 subagents running at the same time**. Start the next agent only when a slot is free.

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

Reviewer count N = 10 unless `--reviewers` was given.

Tell the user in one line: stack, size, chosen N.

## Phase 2 — Security review (10 reviewers, max. 5 running at once)

One reviewer per lens (N=10):

| ID | Lens | Covers |
|---|---|---|
| R1 | Authentication & sessions | login/registration/reset flows, password handling, JWT/session/cookie flaws, OAuth/OIDC/SAML flow bugs, MFA bypass, API-key handling, brute-force protection on auth |
| R2 | Authorization & tenant isolation | missing/wrong access checks, IDOR/BOLA, privilege escalation, role/permission logic, multi-tenant isolation, admin endpoints, GraphQL/RPC field-level auth |
| R3 | Injection | SQL/NoSQL/LDAP/XPath injection, OS command injection, template injection, header/CRLF injection, expression/eval injection |
| R4 | Files, deserialization & outbound requests | path traversal/zip-slip, file upload, unsafe deserialization, XXE, SSRF, prototype pollution, unsafe archive/image/PDF processing |
| R5 | Secrets & cryptography | hardcoded credentials/keys, secrets in repo/config/images, weak or misused crypto, insecure randomness for tokens, signature/MAC verification flaws, TLS verification disabled |
| R6 | Data exposure & API surface | sensitive data in logs/errors/responses, mass assignment, over-exposed API fields, verbose errors, debug endpoints, CSRF on state-changing APIs, CORS misconfig |
| R7 | Client-side / web surface | stored/reflected/DOM XSS, unsafe HTML rendering, open redirect, postMessage, CSP gaps that matter, clickjacking on sensitive actions, token storage in browser |
| R8 | CI/CD, containers & IaC | GitHub Actions script injection, `pull_request_target`, unpinned/untrusted actions, Dockerfiles, k8s/Terraform/Helm misconfig, default/debug config, exposed ports/services |
| R9 | Dependencies & supply chain | reachable vulnerable dependencies, typosquat/suspicious packages, install/postinstall scripts, lockfile integrity, vendored code, build-time fetch of unpinned artefacts |
| R10 | Logic, concurrency & abuse | race conditions/TOCTOU, business-logic abuse, payment/quota/state-machine flaws, replay, unsafe workflow defaults, background jobs/webhooks trust |

If a lens clearly does not apply (e.g. no web frontend), give that reviewer the most relevant hotspots of a neighbouring lens instead and say so.

### Concurrency (hard rule)

At most **5 subagents may run at the same time**. Launch R1–R5 **in a single message**. Then start R6…R10 one by one, each as soon as a running reviewer has finished (rolling window of 5). Never launch more than the free slots allow. Use `subagent_type: "security-audit:security-reviewer"`. Each prompt must contain:
- the target root and commit,
- the **full repo map** from Phase 1 (paste it, don't summarise),
- its reviewer ID (`R1`…`R10`), its lens with the "Covers" text,
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

Launch **3** agents **in a single message** (only after all reviewers are finished, so at most 3 run at once) with `subagent_type: "security-audit:finding-validator"`. All three receive **the full candidate list** (every finding, with all fields) and the severity table. Each gets a different lens:

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
Date, target root, reviewers (10) + lenses, validators.

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
