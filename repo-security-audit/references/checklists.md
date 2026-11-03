# Security review checklists

These are questions to think with, not grep patterns and not a limit on scope. An item here is not a finding until it is traced through real code. Skip what does not apply to the stack. Paste the matching section into each reviewer's prompt.

## Section 1: Authentication, authorization, business logic

**Authentication**
- Does every non-public route pass through authentication? Look for routes registered outside the protected group, alternate mount points, and method or path variations (HEAD, trailing slash, case, encoding).
- What happens when the auth check throws or a dependency is down: fail closed or open?
- Are password reset, email change, invite, magic link and MFA flows bound to the right user, single-use, expiring and unguessable? Can MFA be skipped by going directly to the next step?
- Are there debug logins, default accounts, or test backdoors reachable in production configuration?

**Tokens and sessions**
- JWT: signature actually verified, algorithm pinned, `iss`, `aud`, `exp` checked, key source not attacker-influenced (`kid`, `jku`, `x5u`)? Is a decode-only function used anywhere for a security decision?
- OAuth/OIDC: `state`, PKCE and nonce validated, redirect URIs matched exactly, account linking based on a verified identifier?
- Sessions: rotated on login and privilege change, invalidated on logout and password change, cookie flags appropriate to the deployment?
- Are API keys and tokens scoped, revocable, and compared safely?

**Authorization**
- Is the check performed on the object actually loaded, using server-side identity, rather than a client-supplied ID?
- Do all routes to a resource (REST, GraphQL, admin, export, jobs, websocket) enforce the same rule? Do nested GraphQL resolvers or list endpoints skip it?
- Can mass assignment set role, owner, tenant or price fields?
- Is the role read from a client-writable claim or header? Do proxies set trusted headers that clients can also send?
- Multi-tenancy: is the tenant filter applied at every query, in caches, search indexes, storage paths and background jobs?

**Business logic and concurrency**
- Are state transitions enforced server-side? Can steps be skipped, repeated or reordered?
- Do balances, quotas, coupons, one-time tokens and invites hold under concurrent requests? Look for check-then-act without locking or a constraint.
- Are prices, amounts and limits taken from the client? What about negative, zero, huge or overflowing values?
- Are webhooks and callbacks that change state authenticated and protected against replay?

## Section 2: Injection, input handling, data security

**Injection**
- SQL/NoSQL: is any query built by concatenation, including `ORDER BY`, table names, raw fragments in an ORM, and operator injection through JSON bodies?
- Command: any shell invocation with interpolated input, or argument injection into safe-looking exec calls (`--upload-pack`, `-o`)?
- Template and expression engines: can user input reach template source, or an expression language or `eval`?
- Header, log, LDAP, XPath, regex (catastrophic backtracking with real leverage).

**Server-side requests and files**
- SSRF: can a user-supplied URL reach internal services or cloud metadata? Are redirects, DNS rebinding, and alternate IP encodings handled, or is validation done on a different parse than the request?
- Path traversal: is the resolved path checked after normalization, considering encoding, symlinks and archive extraction (zip slip)?
- Uploads: are type, size, name and storage location controlled? Can an upload be served from the app origin or executed? Are parsers (image, PDF, XML, archive) exposed to hostile files?

**Client-side**
- XSS: where does stored or reflected input reach raw HTML sinks (`dangerouslySetInnerHTML`, `v-html`, `innerHTML`, unescaped templates), including markdown and rich text renderers? Is it in a privileged context?
- CSRF for cookie-authenticated state changes, CORS with reflected origin and credentials, open redirects chained into token theft, `postMessage` handlers without origin checks.

**Deserialization and object handling**
- Unsafe deserialization (`pickle`, Java native, YAML unsafe load, PHP `unserialize`, `BinaryFormatter`) on data an attacker can influence.
- XXE in XML parsers.
- Prototype pollution through deep merges or path setters on untrusted JSON, with a real gadget to reach impact.

**Cryptography and data**
- Is the construction right for its purpose: authenticated encryption, nonce uniqueness, signature coverage, replay protection, domain separation?
- Is randomness for tokens cryptographically secure? Are secret comparisons constant-time where timing is measurable?
- Password storage: a slow, salted hash with reasonable parameters?
- Sensitive data: does it leak through error responses, logs, API over-fetching, URLs, caches or client bundles?

**Parsing and trust boundaries**
- Do two components parse the same input differently (URL, path, JSON duplicate keys, Unicode, multiple parameters)?
- Is data trusted because it came from "inside" (database, queue, internal service) when an attacker can influence it earlier?

## Section 3: Infrastructure, dependencies, security architecture

**Secrets and configuration**
- Are live credentials committed, including in history-visible config, fixtures, images or client bundles? Distinguish real values from placeholders, and report without reproducing them.
- Dangerous defaults: debug mode, permissive CORS, default passwords, disabled TLS verification, auth off unless configured. Does production configuration actually override them?
- Do error handlers, admin panels, metrics, profilers or API docs get exposed in production?

**Dependencies and supply chain**
- Which version is actually resolved in the lockfile? Is the vulnerable function used, and can attacker input reach it? Without both, it is not a finding.
- Is there a lockfile at all for deployed apps? Risks from unpinned sources, dependency confusion through private package names on a public registry, install scripts, or git dependencies on mutable refs?

**CI/CD**
- `pull_request_target` or `workflow_run` checking out and executing untrusted PR code with secrets?
- Script injection through `${{ github.event.* }}` in `run:` steps?
- Workflow token permissions wider than needed; secrets exposed to forks; third-party actions pinned to mutable tags in sensitive workflows?
- Self-hosted runners executing public PRs; release and publish pipelines a contributor could influence?

**Containers and deployment**
- Privileged containers, host mounts, the Docker socket, `hostNetwork`, added capabilities, running as root combined with a real path to compromise?
- Kubernetes RBAC wider than the workload needs; service account tokens auto-mounted into exposed workloads; missing network isolation for sensitive services?
- Are secrets baked into image layers or passed as build arguments?

**Cloud and IAM**
- Wildcard IAM actions or resources on exposed workloads; public buckets; open security groups for databases and admin ports; public snapshots?
- Is Terraform state or a similar file containing secrets exposed? Do OIDC trust policies restrict repo and branch?

**Integrations and architecture**
- Are incoming webhooks signature-checked over the raw body, in constant time, with replay protection?
- Are service-to-service calls authenticated, or does "internal" rely on an assumption the network does not enforce?
- Missing control with exploitable consequence: no rate limit on a login or code-verification endpoint where brute force is feasible, or no authorization boundary between components. Show the resulting failure; absence alone is not a vulnerability.
