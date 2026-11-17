# Sweeper lenses

A sweeper hunts one vulnerability class across the whole repository. It owns no files; component owners already read every file in depth. The sweeper's value is consistency: the one endpoint, query or path that the others handle differently.

Each section is `## key — Title`. The script reads this file; do not rename keys without updating `SWEEPER_GROUPS` in `scripts/dsr.py`. With only 2-3 sweepers per review, one sweeper carries several lenses; each lens goes to exactly one sweeper.

## authz — Authentication and access control

Enumerate first, then verify. Record the counts in `swept`.

1. List every entry point: HTTP routes and controllers, RPC and GraphQL resolvers, CLI commands reachable by users, webhook and callback handlers, background-job entry points that take external data, WebSocket and signaling handlers.
2. For each one, find where authentication and authorization are enforced (attributes, decorators, middleware, route config, explicit checks). Flag any entry point that is public by accident, or that relies on a check which a sibling endpoint does not repeat.
3. Object-level checks: wherever an ID, token or name selects an object, verify the caller is checked against that object (owner, member, tenant, role), not only logged in. Check list, search, export, bulk and "by token" variants, which often miss the check that the main endpoint has.
4. Privilege boundaries: role and permission checks that compare the wrong thing, can be bypassed by changing a parameter, or trust a client-supplied role, user ID or flag. Mass assignment into privileged fields.
5. Authentication flows: login, password reset, invitation, guest and share links, API tokens, app passwords, OAuth and SSO callbacks (state, redirect URI, account linking), session fixation.
6. Cross-tenant and cross-server paths: federation, shared resources, guest access.

## injection — Injection and unsafe interpreters

Enumerate every sink first, then trace each back to its sources. Record sink counts per class in `swept`.

1. SQL and other query languages: raw queries, string-built `WHERE`, `ORDER BY`, `LIMIT`, table or column names from input, query-builder escape hatches, `LIKE` wildcards, NoSQL operators, LDAP filters.
2. OS commands and process spawning: shell strings, argument injection (a value starting with `-`), unsafe `PATH` or working-directory use.
3. Code and expression evaluation: `eval`, dynamic `include` or `require`, template engines fed with user-controlled template text, expression languages, dynamic class or method names from input, reflection.
4. Deserialization: native serialization formats, YAML with unsafe loaders, pickle-like formats, any `unserialize` of data an attacker can influence (cookies, cache entries, uploaded files, message bodies).
5. XML: external entities and DTDs in parsers, XSLT, SVG handling.
6. Header, log and mail injection: CRLF in headers, redirects, mail headers and subjects.
7. For every sink, check whether the source is attacker-controlled under the threat model and which sanitization, escaping or parameter binding stands in between.

## ssrf-files — SSRF, path traversal, file handling and outbound requests

1. Outbound requests: every place the server fetches a URL or connects to a host that an attacker can influence (link previews, webhooks, federation, avatar and image fetchers, import-from-URL, bot callbacks, push and SIP/TURN/STUN endpoints). Check scheme and host allowlists, redirects, DNS rebinding, internal and link-local addresses, port handling, IPv6 and URL-parsing differences.
2. Path traversal: any file path built from input (names, tokens, IDs, archive entries), `..` handling, absolute paths, symlinks, null bytes, encoding tricks, normalization before versus after the check.
3. Uploads and downloads: type and extension checks, storage location and executable-by-the-web-server risk, filename handling, content-type and `Content-Disposition` handling, inline rendering of attacker-supplied HTML or SVG, size limits that matter for security.
4. Archive and file-format parsing: zip-slip, decompression of attacker-supplied archives, image and document processing with attacker-supplied files.
5. Temporary files, predictable names, world-readable output, race between check and use on files.
6. Open redirects: redirect targets built from input, including after login and in OAuth flows.

## web-client — Browser-side and HTTP-layer attacks

1. XSS: every place untrusted data reaches HTML, an attribute, a URL, JavaScript, CSS or markdown. In frontends: raw HTML binding (`v-html`, `innerHTML`, `dangerouslySetInnerHTML`, `document.write`), sanitizer configuration and bypasses, link and image URL schemes (`javascript:`, `data:`), markdown and rich-text rendering, user-controlled filenames, display names and room or document titles shown in other users' views, server-rendered templates with escaping turned off.
2. CSRF: state-changing requests that rely on cookies without a CSRF token or equivalent, and that the framework does not already protect; GET requests that change state; token checks that can be skipped.
3. CORS, `postMessage` handlers without origin checks, `window.opener`, iframe embedding and clickjacking where the page performs sensitive actions, content-security-policy gaps only where they make a concrete XSS exploitable.
4. Cookies and storage: session or token material in places script can read when XSS is plausible, tokens in URLs that leak through referrers or logs.
5. HTTP-layer: host-header trust in generated links (password reset poisoning), request smuggling-relevant parsing in code the project owns, response splitting, cache poisoning of authenticated content.

## crypto-secrets — Crypto, tokens, sessions and secrets

Start from `secret-leads.tsv` in the work directory (locations of pattern matches; values are deliberately not stored). Triage each lead from the file itself: real secret, example, test fixture or placeholder.

1. Hard-coded credentials, keys, tokens and salts in source, config and CI files; secrets with a default value that deployments are likely to keep. Refer to a secret by location and kind only. Never copy it into your output.
2. Randomness: security tokens, IDs, passwords, nonces or invitation codes generated with a non-cryptographic generator, too short, or derived from guessable values.
3. Token and session handling: JWT and signed-token validation (algorithm confusion, missing signature or expiry checks, wrong audience), session lifetime and invalidation after logout or password change, token scope, replay, predictable or enumerable tokens, tokens stored unhashed where a database leak would matter.
4. Password and key handling: hashing algorithm and parameters, comparison in non-constant time where timing is observable, key derivation, key and IV reuse, ECB or unauthenticated encryption, certificate and signature verification that is disabled or incomplete, TLS verification turned off.
5. End-to-end or signed-message protocols the project implements itself: missing authentication of the peer, downgrade, replay.

## logic-abuse — Race conditions, business-logic abuse and brute force

1. Check-then-act on security decisions: permission, quota, ban, lock or expiry checked in one step and acted on in another without a transaction or lock (TOCTOU); double-spend style races on invitations, tokens, one-time links and counters.
2. State machines that can be driven out of order: skipping verification, reusing a consumed token, acting on an object after access was revoked, changing ownership or role through a side channel.
3. Rate limiting and brute force: login, password reset, token and PIN guessing, invitation and share-link guessing, enumeration of users, rooms or objects. Check whether the protection exists and whether it can be bypassed (per-IP only, header-spoofable, resettable).
4. Mass assignment and parameter tampering: fields a client may set that should be server-controlled (role, owner, price, status, tenant, permission bitmasks).
5. Features that let one user act on another at scale (mentions, notifications, invitations, bots, bridges) when that crosses a permission boundary.
6. Trust of data from other servers, bots or integrations without verifying origin and signature.

## config-cicd — Deployment, CI/CD, build and configuration

1. CI/CD workflows: untrusted input in `run:` steps or scripts (issue and PR titles, branch names, commit messages), `pull_request_target` or `workflow_run` that checks out and runs untrusted code, secrets exposed to forks, overly broad token permissions, unpinned third-party actions that run with secrets, artifact and cache poisoning.
2. Container and deployment files: running as root without need, secrets baked into images or build args, exposed debug ports, permissive default credentials, writable volumes that cross trust boundaries.
3. Application configuration: insecure defaults that ship enabled (debug mode, verbose errors that leak secrets, open registration, default admin accounts, permissive allowlists), sample configs copied verbatim into production, security switches that default to off.
4. Build and install scripts: download-and-execute without verification, scripts that interpolate untrusted values, install hooks.
5. Dependency manifests: only dependencies that are typosquat-like, fetched from unverified sources, or pinned to a vulnerable version whose vulnerable function the project demonstrably calls. A plain outdated version is out of scope.
6. Infrastructure-as-code: public exposure, missing authentication, wildcard permissions.
