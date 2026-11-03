# Severity classification

Only three levels exist. Paste this file into every review and validation prompt.

**P0 — Critical.** A critical vulnerability with catastrophic or system-wide impact, such as a realistic unauthenticated full-system compromise or similarly severe security failure requiring immediate action.

**P1 — High.** A serious, exploitable vulnerability that can cause substantial unauthorized access, privilege escalation, sensitive data compromise, or significant system compromise.

**P2 — Medium.** A credible, actionable security vulnerability with meaningful impact but more limited exploitation conditions, scope, or consequences.

**Below P2 — not reported.** P3, P4, informational issues, generic best practices, code style, maintainability suggestions, and hardening advice without an attack path.

## How to decide

Weigh all of these using what the code shows:

| Factor | Pushes severity down when |
|---|---|
| Attack prerequisites | The attacker needs an account, a specific role, or prior access |
| Required privileges | The attacker already has most of what they would gain |
| Exposure | The path is internal only or needs an unusual configuration |
| Exploit complexity | It needs a precise race, victim interaction, or unlikely conditions |
| Blast radius | It affects one user or low-value data rather than all tenants or core secrets |
| Existing protections | Partial mitigations limit what is achievable |

Rules:

- **Never inflate.** When two levels both seem plausible, choose the lower. Inflated ratings damage the credibility of the whole report.
- **A missing control is not automatically a vulnerability.** Demonstrate the exploitable failure.
- **An admin doing what admins can do is usually not a vulnerability**, unless it crosses a real boundary, such as tenant admin to platform admin.
- **A dependency CVE takes its severity from its impact in this application**, not its CVSS score.
- **Rate by the worst realistic chain only if the whole chain is demonstrated.** Do not assume a second bug that has not been shown.
- **One root cause is one finding,** with all its locations, unless the manifestations need independent fixes or differ in impact.

## Calibration examples

These are illustrations, not fixed mappings. Prerequisites and impact in the actual code decide.

- **P0:** Pre-auth RCE in a public service. Authentication bypass giving full admin. Committed live production cloud credentials with broad rights.
- **P1:** IDOR exposing other users' sensitive records to any logged-in user. SQL injection behind login that reads the whole database. Tenant isolation failure. CI workflow that hands repository secrets to external PR authors.
- **P2:** Stored XSS requiring victim interaction with limited session impact. SSRF limited to selected internal hosts with no response returned. Race allowing a coupon to be used twice. Limited disclosure of non-critical data across accounts.
