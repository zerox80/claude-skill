# Phase 1: Reconnaissance guide

Goal: understand the system well enough that three reviewers can cover all of it, and leave a map that shows what was and was not covered. Start from `inventory.jsonl` and the summary the `inventory` command prints. Its categories and exclusion hints come from path heuristics, so check them.

## What to inspect

Read the relevant files. Filenames and keyword hits only tell you where to look.

- Repository structure; applications, services, packages and workspaces
- Entry points, routes, APIs, controllers, middleware, CLI commands, RPC handlers
- Authentication, authorization, sessions, permissions
- Business logic and data access layers
- Database schemas, migrations, queries
- Configuration files and environment variable usage
- Dependencies and lockfiles
- Docker, Kubernetes, Terraform and deployment configuration
- CI/CD pipelines and GitHub Actions
- Background jobs, workers, queues, scheduled tasks
- File uploads, external integrations, webhooks
- Cryptography, secrets handling, sensitive data processing
- Tests and security-relevant documentation (which can reveal intended behavior; they do not prove actual behavior)

For a very large repository, read every entry point, auth component and security-critical module, plus enough of the rest to describe each unit accurately. Reviewers do the deep reading. Record anything you only skimmed as such.

## Write `recon.md`

Derive this from the code, not the README:

- **System overview:** what runs, how it is deployed, and what is actually exposed.
- **Sensitive assets:** data, keys, accounts, money, and integrity of results.
- **Actors and roles:** anonymous, authenticated, per role, tenant, admin, internal service, CI contributor, operator.
- **Attacker-controlled inputs:** requests, headers, uploads, webhooks, queue messages, stored data rendered later, PR content in CI, third-party responses.
- **Trust boundaries:** where data crosses into a more trusted context, and where validation and authorization actually happen.
- **Critical data flows:** source to sink for the most sensitive operations.
- **Invariants:** what must always hold, such as "tenant A never reads tenant B".
- **Framework guarantees:** which protections are relied on, with versions. Reviewers need this to judge mitigations.

## Write `coverage.json`

```json
{
  "units": [
    {
      "id": "U01",
      "name": "API service",
      "kind": "application",
      "paths": ["apps/api/"],
      "reviewers": [1, 2, 3],
      "notes": "Public HTTP API; JWT auth middleware in src/middleware/auth.ts"
    }
  ],
  "exclusions": [
    {"path": "vendor/", "reason": "Unmodified third-party code, version pinned in go.mod; checked by reviewer 3 at the dependency level"}
  ],
  "could_not_inspect": [
    {"path": "assets/plugin.bin", "reason": "Compiled binary, no source available"}
  ]
}
```

Rules:

- `kind` is one of `application`, `package`, `service`, `subsystem`, `infrastructure`, `ci`, `other`.
- `paths` entries are exact files, directory prefixes ending in `/`, or globs.
- **Every inventoried file must match a unit or an exclusion.** The gate enforces this.
- **Every application and package needs its own unit**, in monorepos too. The gate fails if a directory containing a package manifest is only covered by a broader parent unit or nothing at all. Fixture or example packages can be excluded with a reason.
- Assign all three reviewers to a unit by default, since auth, input and infrastructure flaws can appear anywhere. Drop a reviewer only when its lens clearly does not apply, such as Reviewer 1 on a Terraform-only unit.
- Size units by subject, and keep security-critical code in its own unit even when small, so that coverage reports stay meaningful.

## Exclusions

Exclude generated or vendored files unless they materially affect security. Keep these in scope even if they look ignorable:

- Vendored code with local patches
- Generated code that parses input or enforces access, such as RPC stubs and ORM layers with custom templates
- Committed build output that gets deployed
- Lockfiles, which Reviewer 3 needs

Every exclusion needs a real reason, and it appears in the report.

Git-ignored files are listed in `inventory_ignored.txt` and are not part of the repository. Do not open ignored files that may hold real secrets, such as `.env`. Mention that they exist only if their presence matters.
