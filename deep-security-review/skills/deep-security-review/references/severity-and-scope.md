## Severity and scope (security only)

Report **P0, P1 and P2 only**. Judge severity by what a real attacker can achieve in a default or realistic deployment, using the attacker model in `recon.md`. Use the lowest severity that fits.

- **P0, critical.** A remote attacker with no account, or with any ordinary account, obtains code execution on the server, a full authentication bypass, takeover of arbitrary accounts, read or write access to other tenants' or all users' data, or a live secret that grants the same. No unusual preconditions.
- **P1, high.** An authenticated low-privilege user reads or changes other users' sensitive data (IDOR/BOLA) or escalates privileges; SQL, command, template or expression injection reachable by an authenticated user; stored XSS that runs in another user's or an administrator's session; SSRF that reaches internal services or cloud metadata; arbitrary file read, write or path traversal; forged or replayable tokens; broken crypto that exposes protected data; or a P0-class impact that needs exactly one realistic precondition (victim interaction, a common non-default setting).
- **P2, medium.** Reflected or DOM XSS that needs a victim to click; CSRF on a meaningful state change; missing authorization on a low-sensitivity function; limited information disclosure that enables real attacks (account enumeration of valuable accounts, partial personal data, internal details); open redirect with a real phishing or OAuth consequence; missing brute-force protection on a credential or token endpoint where abuse is demonstrable; a race condition that gives a limited bypass; a security-relevant insecure default with realistic exposure.

Anything below P2 is not reported. Zero findings for an area is a good result when that is what the code supports. Never pad the list.

### Out of scope: do not report

- Denial of service, resource exhaustion and regex backtracking, unless it is also an authentication or authorization bypass.
- Missing hardening or best practice with no attack path (headers, cookie flags, "should use X") and anything you can only describe with "could" or "might" without a concrete trigger.
- Vulnerable dependency versions, unless the application calls the vulnerable code path in a way an attacker can reach. Name the call site.
- Attacks that need the attacker to already be an administrator, root or the host. Administrator-supplied settings, environment variables, command-line arguments and config files are trusted input unless `recon.md` says otherwise.
- Test, fixture, example and documentation code. Obviously fake secrets in fixtures.
- Client-side checks when the server enforces the same rule. Missing audit logging. Logging of non-secret data.
- Memory-safety bugs in memory-safe languages. Style, naming, refactoring, licensing.
- Behavior the framework documents as intended and the project relies on.

### What every finding needs

1. **Attacker:** who exactly (anonymous, any user, user of another tenant, remote federated server, malicious file author, ...) and which privileges they already hold.
2. **Source:** the attacker-controlled input or action, with file and line.
3. **Path:** every hop from the source to the vulnerable operation, with file and line per hop.
4. **Protections checked:** the guards, validation, middleware, framework defaults, database constraints and configuration you looked for, and why each does not stop the attack.
5. **Exploit scenario:** concrete steps or request an attacker would send.
6. **Impact:** what is gained, for whom, at what scale.
7. **Severity justification:** which rule above applies.

A finding without all seven is a hypothesis, not a finding.
