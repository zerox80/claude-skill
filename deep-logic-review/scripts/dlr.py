#!/usr/bin/env python3
"""Bookkeeping and phase gates for the deep-logic-review skill (stdlib only).

The model does the reviewing; this script keeps it honest about what the
review covered and blocks each phase until the previous one is really done.
It never writes to the repository, and it refuses a work directory inside it.

  init REPO --work DIR [--scope SUBPATH]...   inventory the repo, create ledger
  reclass WORK --glob G --category C --reason R   correct a classification
  assign WORK --map MAP.json                  give every required file one owner
  audit WORK                                  coverage from the reviewers' files
  candidates WORK [--allow-incomplete R1=why] validate findings, assign IDs
  partition WORK [--merge KEEP:DUP]...        write blinded claim sheets
  sandbox WORK NAME                           disposable repo copy for test runs
  report WORK                                 validate verdicts, write skeleton
  check-report WORK REPORT.md                 final gate on the finished report

Exit codes: 0 ok, 2 the gate failed (the printed errors say what to fix).
"""
import argparse
import csv
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

REVIEWERS = ["R1", "R2", "R3"]
VALIDATORS = ["V1", "V2", "V3"]
SEVERITIES = ["P0", "P1", "P2"]
LEDGER_FIELDS = ["path", "category", "lines", "required", "owner", "status", "note"]
COVERAGE_STATUSES = {"full", "partial", "skipped"}
VERDICTS = {"CONFIRMED", "REJECTED", "NEEDS_MORE_EVIDENCE"}
REPRO_STATUSES = {"reproduced", "not-reproduced", "not-attempted"}
REJECTION_CATEGORIES = {
    "unreachable": "The path cannot occur in real execution",
    "guarded": "An existing guard or protection already handles it",
    "intended": "The behavior is intentional or documented",
    "invalid-input": "It requires input outside the application's real contracts",
    "below-threshold": "Real, but below P2",
    "speculative": "The claim rests on unsupported assumptions",
    "misread-code": "The code does not behave as the claim describes",
    "other": "Other",
}
REQUIRED_CATEGORIES = {"source", "config", "schema"}
CATEGORIES = REQUIRED_CATEGORIES | {"test", "docs", "other", "excluded"}

VENDOR_DIRS = {
    "node_modules", "vendor", "vendored", "third_party", "thirdparty", "third-party",
    "3rdparty", "bower_components", "dist", "build", "target", "out", ".next", ".nuxt",
    "__pycache__", ".venv", "venv", ".tox", ".gradle", ".idea", ".vscode", ".git",
    "coverage", ".cache", ".terraform", "Pods",
}
LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "Pipfile.lock",
    "Cargo.lock", "composer.lock", "Gemfile.lock", "go.sum", "uv.lock", "bun.lock",
    "flake.lock", "packages.lock.json",
}
ASSET_EXT = {
    "png", "jpg", "jpeg", "gif", "ico", "icns", "svg", "webp", "bmp", "tiff", "woff", "woff2",
    "ttf", "otf", "eot", "mp3", "mp4", "wav", "ogg", "webm", "mov", "pdf", "zip", "gz", "tgz",
    "tar", "bz2", "xz", "7z", "rar", "jar", "war", "class", "so", "dylib", "dll", "exe", "o",
    "obj", "a", "lib", "pyc", "pyo", "wasm", "map", "bin", "dat", "db", "sqlite", "sqlite3",
    "msi", "msix", "dmg", "deb", "rpm", "apk", "aar", "psd", "ai", "xcf", "qm",
}
SOURCE_EXT = {
    "py", "pyi", "js", "jsx", "mjs", "cjs", "ts", "tsx", "vue", "svelte", "java", "kt", "kts",
    "scala", "groovy", "go", "rs", "c", "h", "cc", "cpp", "cxx", "hpp", "hh", "hxx", "m", "mm",
    "swift", "cs", "fs", "vb", "rb", "php", "pl", "pm", "lua", "dart", "ex", "exs", "erl",
    "clj", "cljs", "hs", "ml", "mli", "r", "jl", "zig", "nim", "sol", "sh", "bash", "zsh",
    "ps1", "psm1", "bat", "cmd", "qml", "awk", "tcl", "html", "htm", "ejs", "erb", "jinja",
    "j2", "hbs", "tf", "cairo", "move", "wat", "asm", "s", "ui",
}
CONFIG_EXT = {
    "yml", "yaml", "toml", "ini", "cfg", "conf", "properties", "cmake", "gradle", "xml",
    "json", "json5", "plist", "tfvars", "editorconfig", "in", "mk", "nix", "bzl", "pro", "pri",
}
CONFIG_NAMES = {
    "makefile", "dockerfile", "jenkinsfile", "cmakelists.txt", "justfile", "rakefile",
    "gemfile", "procfile", "vagrantfile", "build", "workspace", "containerfile", "brewfile",
}
SCHEMA_EXT = {"sql", "prisma", "graphql", "gql", "proto", "avsc", "thrift", "xsd", "edmx"}
SCHEMA_DIRS = {"migrations", "migrate", "alembic", "flyway", "liquibase", "db", "schemas"}
DOC_EXT = {"md", "markdown", "rst", "adoc", "txt", "org", "tex"}
TEST_DIRS = {
    "test", "tests", "__tests__", "__test__", "spec", "specs", "testing", "fixtures",
    "e2e", "testdata", "test_data", "__mocks__", "mocks",
}
TEST_NAME = re.compile(
    r"(^test_|^tst_|_test\.|\.test\.|\.spec\.|_spec\.|test\.(java|kt|cs|cpp|go)$|tests\.(java|kt|cs|cpp)$)",
    re.I,
)
TRANSLATION_DIRS = {"translations", "translation", "locale", "locales", "i18n", "l10n", "lang"}
TRANSLATION_EXT = {"po", "pot", "xlf", "xliff", "resx", "strings", "arb"}
SENSITIVE_NAME = re.compile(
    r"(^\.env(\..+)?$|\.(pem|key|p12|pfx|jks|keystore|ppk|gpg|asc)$|^id_(rsa|dsa|ecdsa|ed25519)$"
    r"|^credentials(\.\w+)?$|^secrets?(\.\w+)?$|^\.npmrc$|^\.pypirc$|^\.netrc$|^\.htpasswd$)",
    re.I,
)
SENSITIVE_OK = re.compile(r"\.(example|sample|template|dist|defaults?)$", re.I)
GENERATED_MARK = re.compile(
    r"@generated|do not edit|code generated by|auto-?generated|generated by .{0,40}(protoc|moc|uic|rcc|openapi|swagger|thrift)",
    re.I,
)
SECRET_PATTERNS = [
    re.compile(p)
    for p in (
        r"AKIA[0-9A-Z]{16}",
        r"ASIA[0-9A-Z]{16}",
        r"gh[pousr]_[A-Za-z0-9]{30,}",
        r"github_pat_[A-Za-z0-9_]{30,}",
        r"glpat-[A-Za-z0-9_-]{16,}",
        r"xox[abpsr]-[A-Za-z0-9-]{10,}",
        r"sk-[A-Za-z0-9_-]{24,}",
        r"AIza[0-9A-Za-z_-]{30,}",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"eyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}",
    )
]


class GateError(Exception):
    def __init__(self, errors):
        super().__init__("gate failed")
        self.errors = errors if isinstance(errors, list) else [errors]


# --- helpers ---------------------------------------------------------------


def glob_regex(pattern):
    """Glob with ** support. A bare directory name matches everything below it."""
    pattern = pattern.strip().removeprefix("./")
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += r"(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            out += r".*"
            i += 2
        elif pattern[i] == "*":
            out += r"[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += r"[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(rf"^{out.removesuffix('/')}(?:/.*)?$")


def run_git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)


def tree_fingerprint(repo):
    head = run_git(repo, "rev-parse", "HEAD")
    if head.returncode != 0:
        return None
    status = run_git(repo, "status", "--porcelain=v1", "--untracked-files=all", "--ignored", "--no-renames")
    branch = run_git(repo, "symbolic-ref", "-q", "HEAD")
    payload = head.stdout + b"\0" + status.stdout + b"\0" + branch.stdout
    return {"head": head.stdout.decode().strip(), "digest": hashlib.sha256(payload).hexdigest()}


def list_files(repo):
    """Tracked plus untracked-not-ignored files; falls back to a walk without git."""
    if run_git(repo, "rev-parse", "--is-inside-work-tree").returncode == 0:
        prefix = run_git(repo, "rev-parse", "--show-prefix").stdout.decode().strip()
        listed = run_git(repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard").stdout
        names = {n.decode("utf-8", "surrogateescape") for n in listed.split(b"\0") if n}
        return sorted(names), bool(prefix)
    names = []
    for root, dirs, files in os.walk(repo, followlinks=False):
        dirs[:] = [d for d in dirs if d not in {".git", "node_modules", "__pycache__", ".venv", "venv"}]
        for name in files:
            names.append(os.path.relpath(os.path.join(root, name), repo))
    return sorted(names), False


def classify(repo, rel):
    """Return (category, note, line_count)."""
    path = Path(repo) / rel
    parts = rel.split("/")
    dirs, name = parts[:-1], parts[-1]
    lower = name.lower()
    ext = lower.rsplit(".", 1)[-1] if "." in lower else ""
    if path.is_symlink():
        return "excluded", "symlink", 0
    if not path.is_file():
        return "excluded", "submodule-or-missing", 0
    hit = next((d for d in dirs if d in VENDOR_DIRS), None)
    if hit:
        return "excluded", f"vendored-or-build:{hit}", 0
    if name in LOCKFILES:
        return "excluded", "lockfile", 0
    # credentials.py or Credentials.qml is code; secrets.sh may really hold secrets.
    is_code = ext in SOURCE_EXT - {"sh", "bash", "zsh"}
    if SENSITIVE_NAME.search(name) and not SENSITIVE_OK.search(name) and not is_code:
        return "excluded", "sensitive", 0
    if ext in ASSET_EXT:
        return "excluded", "binary-or-asset", 0
    try:
        data = path.read_bytes()
    except OSError:
        return "excluded", "unreadable", 0
    if b"\0" in data[:8192]:
        return "excluded", "binary", 0
    if not data.strip():
        return "other", "empty", 0
    lines = data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)
    if ext in TRANSLATION_EXT or (ext == "ts" and data[:200].lstrip().startswith(b"<?xml")):
        return "excluded", "translations", lines
    if ext in {"json", "xml", "yml", "yaml"} and any(d.lower() in TRANSLATION_DIRS for d in dirs):
        return "excluded", "translations", lines
    if lower.endswith((".min.js", ".min.css", ".bundle.js")) or (lines and len(data) / lines > 1000):
        return "excluded", "minified", lines
    if GENERATED_MARK.search(data[:2048].decode("utf-8", "ignore")):
        return "excluded", "generated", lines
    if any(d.lower() in TEST_DIRS for d in dirs) or TEST_NAME.search(name):
        return "test", "", lines
    if lower in CONFIG_NAMES or lower.startswith("dockerfile"):
        return "config", "", lines
    if ext in SCHEMA_EXT or (ext in SOURCE_EXT and any(d.lower() in {"migrations", "alembic"} for d in dirs)):
        return "schema", "", lines
    if ext in SOURCE_EXT:
        return "source", "", lines
    if ext in CONFIG_EXT:
        return "config", "", lines
    if ext in DOC_EXT or lower in {"license", "copying", "authors", "notice", "changelog", "readme"}:
        return "docs", "", lines
    if ".github" in dirs or ".gitlab" in dirs:
        return "config", "", lines
    return "other", "", lines


def base_status(category):
    if category in REQUIRED_CATEGORIES:
        return "yes", "pending"
    return "no", "excluded" if category == "excluded" else "reference"


def read_ledger(work):
    with open(work / "ledger.tsv", newline="", encoding="utf-8", errors="surrogateescape") as fh:
        rows = list(csv.DictReader(fh, delimiter="\t", quoting=csv.QUOTE_NONE))
    for row in rows:
        row["lines"] = int(row["lines"])
    return rows


def write_ledger(work, rows):
    with open(work / "ledger.tsv", "w", newline="", encoding="utf-8", errors="surrogateescape") as fh:
        writer = csv.DictWriter(fh, LEDGER_FIELDS, delimiter="\t", quoting=csv.QUOTE_NONE, escapechar="\\", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def load_state(work):
    path = work / "state.json"
    if not path.exists():
        raise GateError(f"{path} not found. Run init first.")
    return json.loads(path.read_text())


def save_state(work, state):
    (work / "state.json").write_text(json.dumps(state, indent=2))


def load_json(path):
    try:
        return json.loads(Path(path).read_text())
    except FileNotFoundError:
        raise GateError(f"missing file: {path}")
    except json.JSONDecodeError as exc:
        raise GateError(f"{path} is not valid JSON: {exc}")


def module_of(rel):
    parts = rel.split("/")
    return "/".join(parts[:2]) if len(parts) > 2 else (parts[0] if len(parts) == 2 else "(root)")


def check_location(repo, file, lines, where, errors):
    """Cited file must exist inside the repo and the cited lines must exist in it."""
    if not isinstance(file, str) or not file or file.startswith("/") or ".." in file.split("/"):
        errors.append(f"{where}: file must be a repo-relative path, got {file!r}")
        return
    path = Path(repo) / file
    if not path.is_file():
        errors.append(f"{where}: file does not exist: {file}")
        return
    match = re.fullmatch(r"(\d+)(?:-(\d+))?", str(lines))
    if not match:
        errors.append(f"{where}: lines must look like '12' or '12-40', got {lines!r}")
        return
    start, end = int(match.group(1)), int(match.group(2) or match.group(1))
    total = path.read_bytes().count(b"\n") + 1
    if start < 1 or end < start or end > total:
        errors.append(f"{where}: lines {lines} are outside {file} ({total} lines)")


def require_text(obj, fields, where, errors):
    for field in fields:
        value = obj.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{where}: missing or empty field '{field}'")


def span_start(lines):
    return int(str(lines).split("-")[0])


def span_end(lines):
    return int(str(lines).split("-")[-1])


# --- commands --------------------------------------------------------------


def cmd_init(args):
    repo = Path(args.repo).resolve()
    work = Path(args.work).resolve()
    if not repo.is_dir():
        raise GateError(f"not a directory: {repo}")
    if work == repo or repo in work.parents:
        raise GateError(f"work directory {work} is inside the repository. Use a location outside it.")
    work.mkdir(parents=True, exist_ok=True)
    if (work / "state.json").exists() and not args.force:
        raise GateError(f"{work} already holds a review. Use a new directory, or --force to restart.")

    names, nested = list_files(repo)
    scopes = [glob_regex(s) for s in args.scope]
    rows = []
    for rel in names:
        category, note, lines = classify(repo, rel)
        if scopes and not any(s.match(rel) for s in scopes):
            category, note = "excluded", "out-of-scope"
        required, status = base_status(category)
        rows.append(dict(path=rel, category=category, lines=lines, required=required, owner="-", status=status, note=note))
    write_ledger(work, rows)
    save_state(work, {
        "repo": str(repo),
        "scope": args.scope,
        "fingerprint": tree_fingerprint(repo),
        "nested_in_git_root": nested,
        "reclass": [],
        "incomplete": {},
    })
    print_inventory(rows, repo, work)


def print_inventory(rows, repo, work):
    required = [r for r in rows if r["required"] == "yes"]
    print(f"repo: {repo}\nwork: {work}\nfiles listed: {len(rows)}")
    print(f"required for review: {len(required)} files, {sum(r['lines'] for r in required)} lines")
    print("\nby category (files / lines):")
    for cat in sorted(CATEGORIES):
        group = [r for r in rows if r["category"] == cat]
        if group:
            print(f"  {cat:9} {len(group):6} {sum(r['lines'] for r in group):9}")
    ext = Counter()
    for r in required:
        name = r["path"].rsplit("/", 1)[-1]
        ext[name.rsplit(".", 1)[-1].lower() if "." in name else name] += r["lines"]
    print("\nrequired lines by extension:", ", ".join(f"{k}={v}" for k, v in ext.most_common(15)))
    modules = Counter()
    for r in required:
        modules[module_of(r["path"])] += r["lines"]
    print("\nlargest required modules (lines):")
    for name, lines in modules.most_common(25):
        print(f"  {lines:8} {name}")
    if len(modules) > 25:
        print(f"  ... and {len(modules) - 25} more (see ledger.tsv)")
    print("\nexcluded, by reason (check for application-owned logic, then reclass):")
    reasons = defaultdict(list)
    for r in rows:
        if r["category"] == "excluded":
            reasons[r["note"]].append(r["path"])
    for reason, paths in sorted(reasons.items(), key=lambda kv: -len(kv[1])):
        roots = Counter("/".join(p.split("/")[:2]) for p in paths).most_common(4)
        print(f"  {reason}: {len(paths)} [{', '.join(k for k, _ in roots)}]")
    others = [r["path"] for r in rows if r["category"] == "other"]
    if others:
        print(f"\nunclassified text ('other', not required): {len(others)}, e.g. {others[:8]}")


def cmd_reclass(args):
    work = Path(args.work).resolve()
    state = load_state(work)
    if args.category not in CATEGORIES:
        raise GateError(f"category must be one of {sorted(CATEGORIES)}")
    if (work / "assignment.json").exists():
        raise GateError("reviewers are already assigned. Reclassify before assign, then rerun assign.")
    pattern = glob_regex(args.glob)
    rows = read_ledger(work)
    changed = 0
    repo = Path(state["repo"])
    for row in rows:
        if pattern.match(row["path"]):
            if row["note"] == "sensitive" and args.category != "excluded":
                raise GateError(f"{row['path']} looks like a secret file; it stays excluded.")
            row["category"] = args.category
            row["note"] = f"reclass:{args.reason}"
            if row["lines"] == 0 and (repo / row["path"]).is_file():
                row["lines"] = (repo / row["path"]).read_bytes().count(b"\n")
            row["required"], row["status"] = base_status(args.category)
            changed += 1
    if not changed:
        raise GateError(f"pattern matched nothing: {args.glob}")
    state["reclass"].append({"glob": args.glob, "category": args.category, "reason": args.reason, "files": changed})
    write_ledger(work, rows)
    save_state(work, state)
    print(f"reclassified {changed} files as {args.category}")


def cmd_assign(args):
    work = Path(args.work).resolve()
    load_state(work)
    mapping = load_json(args.map)
    unknown = set(mapping) - set(REVIEWERS)
    errors = [f"unknown reviewer {k}; use {REVIEWERS}" for k in sorted(unknown)]
    compiled = {r: [glob_regex(g) for g in mapping.get(r, [])] for r in REVIEWERS}
    rows = read_ledger(work)
    required = [r for r in rows if r["required"] == "yes"]
    unassigned, overlap = [], []
    for row in rows:
        row["owner"] = "-"
    for row in required:
        owners = [r for r in REVIEWERS if any(p.match(row["path"]) for p in compiled[r])]
        if len(owners) > 1:
            overlap.append(f"{row['path']} -> {owners}")
        elif not owners:
            unassigned.append(row["path"])
        else:
            row["owner"] = owners[0]
    if overlap:
        errors.append(f"{len(overlap)} files have more than one owner, e.g. {overlap[:15]}")
    if unassigned:
        errors.append(f"{len(unassigned)} required files have no owner, e.g. {unassigned[:30]}")
    if errors:
        raise GateError(errors)
    write_ledger(work, rows)
    (work / "assignment.json").write_text(json.dumps(mapping, indent=2))
    for rev in REVIEWERS:
        owned = [r for r in required if r["owner"] == rev]
        (work / f"scope-{rev}.txt").write_text("".join(f"{r['lines']}\t{r['path']}\n" for r in owned))
        print(f"{rev}: {len(owned)} files, {sum(r['lines'] for r in owned)} lines -> scope-{rev}.txt")
        if not owned:
            print(f"  note: {rev} owns no files; give it lens targets so it still has real work")


def apply_coverage(work, rows):
    """Recompute ledger status. Only the owner's report can mark a file reviewed."""
    errors = []
    for row in rows:
        if row["required"] == "yes":
            row["status"], row["note"] = "pending", ""
    by_path = {r["path"]: r for r in rows}
    for rev in REVIEWERS:
        path = work / f"review-{rev}.json"
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            errors.append(f"review-{rev}.json is not valid JSON: {exc}")
            continue
        for entry in data.get("coverage", []):
            status = entry.get("status")
            if status not in COVERAGE_STATUSES:
                errors.append(f"review-{rev}.json coverage {entry.get('path')!r}: status must be one of {sorted(COVERAGE_STATUSES)}")
                continue
            pattern = glob_regex(str(entry.get("path", "")))
            exact = by_path.get(entry.get("path"))
            targets = [exact] if exact else [r for r in rows if pattern.match(r["path"])]
            for row in targets:
                if row["required"] == "yes" and row["owner"] == rev:
                    row["status"], row["note"] = status, str(entry.get("note", ""))
    return errors


def coverage_summary(rows):
    required = [r for r in rows if r["required"] == "yes"]
    counts = Counter(r["status"] for r in required)
    modules = defaultdict(Counter)
    for r in required:
        modules[module_of(r["path"])][r["status"]] += 1
    gaps = [r for r in required if r["status"] != "full"]
    return required, counts, modules, gaps


def cmd_audit(args):
    work = Path(args.work).resolve()
    load_state(work)
    if not (work / "assignment.json").exists():
        raise GateError("run assign first")
    rows = read_ledger(work)
    errors = apply_coverage(work, rows)
    if errors:
        raise GateError(errors)
    write_ledger(work, rows)
    required, counts, modules, gaps = coverage_summary(rows)
    for rev in REVIEWERS:
        path = work / f"review-{rev}.json"
        if not path.exists():
            print(f"{rev}: no review file yet")
        else:
            print(f"{rev}: complete={json.loads(path.read_text()).get('complete')}")
    print(f"required files: {len(required)}; " + ", ".join(f"{k}={counts[k]}" for k in ("full", "partial", "skipped", "pending")))
    print("\nmodules with gaps:")
    shown = [(m, c) for m, c in sorted(modules.items()) if set(c) - {"full"}]
    for name, c in shown[:40]:
        print(f"  {name}: " + ", ".join(f"{k}={v}" for k, v in sorted(c.items())))
    if not shown:
        print("  none")
    (work / "coverage-gaps.tsv").write_text(
        "".join(f"{r['owner']}\t{r['status']}\t{r['lines']}\t{r['path']}\t{r['note']}\n" for r in gaps)
    )
    print(f"\ngap files: {len(gaps)} (coverage-gaps.tsv)")


FINDING_TEXT = ["title", "expected", "actual", "trigger", "root_cause", "impact"]


def cmd_candidates(args):
    work = Path(args.work).resolve()
    state = load_state(work)
    repo = Path(state["repo"])
    if not (work / "assignment.json").exists():
        raise GateError("run assign first")
    incomplete = dict(a.split("=", 1) for a in args.allow_incomplete)
    errors, findings = [], []
    for rev in REVIEWERS:
        path = work / f"review-{rev}.json"
        if not path.exists():
            if rev not in incomplete:
                errors.append(f"{rev}: review file is missing; the review phase is not finished")
            continue
        data = load_json(path)
        if data.get("complete") is not True and rev not in incomplete:
            errors.append(f"{rev}: complete is not true; finish it, or pass --allow-incomplete {rev}=reason")
        for i, finding in enumerate(data.get("findings", []), 1):
            where = f"{rev} finding {i}"
            require_text(finding, FINDING_TEXT, where, errors)
            if finding.get("severity") not in SEVERITIES:
                errors.append(f"{where}: severity must be P0, P1 or P2, got {finding.get('severity')!r}")
            check_location(repo, finding.get("file"), finding.get("lines"), where, errors)
            steps = finding.get("execution_path")
            if not isinstance(steps, list) or not steps:
                errors.append(f"{where}: execution_path must list the faulty path")
            else:
                for step in steps:
                    check_location(repo, step.get("file"), step.get("lines"), f"{where} path step", errors)
            finding["reviewer"] = rev
            findings.append(finding)
    if errors:
        raise GateError(errors)
    state["incomplete"] = incomplete
    save_state(work, state)

    findings.sort(key=lambda f: (f["severity"], f["file"], span_start(f["lines"])))
    for i, finding in enumerate(findings, 1):
        finding["id"] = f"C-{i:03d}"
    (work / "candidates.json").write_text(json.dumps(findings, indent=2))
    print(f"candidates: {len(findings)}")
    for f in findings:
        print(f"  {f['id']} {f['severity']} {f['reviewer']} {f['file']}:{f['lines']}  {f['title']}")
    print("\npossible duplicates (same file, overlapping or adjacent lines):")
    any_dup = False
    for i, a in enumerate(findings):
        for b in findings[i + 1:]:
            if a["file"] == b["file"] and span_start(b["lines"]) <= span_end(a["lines"]) + 5 and span_start(a["lines"]) <= span_end(b["lines"]) + 5:
                print(f"  {a['id']} / {b['id']}")
                any_dup = True
    if not any_dup:
        print("  none")


def partition_claims(claims):
    """Greedy balance by weight; same-file claims stay together to avoid duplicate reads."""
    buckets = {v: [] for v in VALIDATORS}
    if len(claims) == 0:
        return buckets
    if len(claims) < 3:
        # Each validator still does real work: the spare ones re-check the most severe claim.
        for validator, claim in zip(VALIDATORS, claims):
            buckets[validator].append(claim)
        spare = VALIDATORS[len(claims):]
        for validator in spare:
            buckets[validator].append(claims[0])
        return buckets
    groups = defaultdict(list)
    for claim in claims:
        groups[claim["file"]].append(claim)
    load = Counter()
    for _, group in sorted(groups.items(), key=lambda kv: -sum(c["_weight"] for c in kv[1])):
        target = min(VALIDATORS, key=lambda v: load[v])
        buckets[target].extend(group)
        load[target] += sum(c["_weight"] for c in group)
    for validator in VALIDATORS:
        while not buckets[validator]:
            donor = max(VALIDATORS, key=lambda v: len(buckets[v]))
            buckets[validator].append(buckets[donor].pop())
    return buckets


def cmd_partition(args):
    work = Path(args.work).resolve()
    load_state(work)
    candidates = load_json(work / "candidates.json")
    by_id = {c["id"]: c for c in candidates}
    errors = []
    merged = {}
    for pair in args.merge:
        keep, _, dup = pair.partition(":")
        if keep not in by_id or dup not in by_id or keep == dup:
            errors.append(f"bad merge {pair!r}; use KEEP:DUP with existing candidate IDs")
        else:
            merged[dup] = keep
    if errors:
        raise GateError(errors)
    claims = []
    for cand in candidates:
        if cand["id"] in merged:
            continue
        dups = [by_id[d] for d, k in merged.items() if k == cand["id"]]
        severities = [cand["severity"]] + [d["severity"] for d in dups]
        # The sheet is blinded: no reviewer identity, reasoning or evidence.
        claims.append({
            "id": cand["id"],
            "claimed_severity": min(severities),
            "title": cand["title"],
            "file": cand["file"],
            "lines": cand["lines"],
            "also_reported_at": [f"{d['file']}:{d['lines']}" for d in dups],
            "claim": cand["actual"],
            "expected_per_claim": cand["expected"],
            "claimed_trigger": cand["trigger"],
            "claimed_impact": cand["impact"],
            "assumptions_to_check": cand.get("assumptions", []),
            "_weight": 2 + len(cand.get("execution_path", [])) + len(dups),
        })
    claims.sort(key=lambda c: (c["claimed_severity"], c["id"]))
    buckets = partition_claims(claims)
    assignment = {}
    for validator, items in buckets.items():
        for claim in items:
            assignment.setdefault(claim["id"], []).append(validator)
        sheet = [{k: v for k, v in c.items() if not k.startswith("_")} for c in items]
        (work / f"claims-{validator}.json").write_text(json.dumps(sheet, indent=2))
    (work / "validation-assignment.json").write_text(json.dumps({"merged": merged, "assignment": assignment}, indent=2))
    print(f"unique claims: {len(claims)} (merged {len(merged)})")
    for validator in VALIDATORS:
        print(f"{validator}: {[c['id'] for c in buckets[validator]]} -> claims-{validator}.json")
    if not claims:
        print("no claims: launch no validators; go straight to report.")


def cmd_sandbox(args):
    work = Path(args.work).resolve()
    state = load_state(work)
    if not re.fullmatch(r"[A-Za-z0-9_-]+", args.name):
        raise GateError("sandbox name may only hold letters, digits, - and _")
    repo = Path(state["repo"])
    dest = work / "sandbox" / args.name
    if dest.exists():
        print(dest)
        return
    copied = 0
    for row in read_ledger(work):
        if row["note"] == "sensitive" or row["note"] == "submodule-or-missing":
            continue
        src, target = repo / row["path"], dest / row["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, target, follow_symlinks=False)
            copied += 1
        except OSError:
            continue
    print(dest)
    print(f"copied {copied} files; secret-like files were left out; dependencies are not included", file=sys.stderr)


def merge_verdicts(cid, entries):
    """All assigned validators must confirm; severity takes the lower claim."""
    verdicts = {e["verdict"] for e in entries}
    if verdicts == {"CONFIRMED"}:
        chosen = max(entries, key=lambda e: e["severity"])
        return {**chosen, "id": cid, "validators": [e["_validator"] for e in entries]}
    if verdicts == {"REJECTED"}:
        return {**entries[0], "id": cid}
    if len(verdicts) > 1:
        reasons = "; ".join(f"{e['_validator']}: {e['verdict']}" for e in entries)
        return {
            "id": cid,
            "verdict": "NEEDS_MORE_EVIDENCE",
            "title": entries[0].get("title", cid),
            "missing_evidence": f"Validators disagreed ({reasons})",
            "_validator": "/".join(e["_validator"] for e in entries),
        }
    return {**entries[0], "id": cid}


def collect_verdicts(work, repo):
    plan = load_json(work / "validation-assignment.json")
    errors, per_claim = [], defaultdict(list)
    for validator in VALIDATORS:
        expected = [cid for cid, vs in plan["assignment"].items() if validator in vs]
        if not expected:
            continue
        path = work / f"verdict-{validator}.json"
        if not path.exists():
            errors.append(f"{validator}: verdict file missing; validation is not finished")
            continue
        got = {}
        for entry in load_json(path).get("verdicts", []):
            got[entry.get("id")] = entry
        for cid in set(got) - set(expected):
            errors.append(f"{validator}: verdict for unassigned claim {cid}")
        for cid in expected:
            entry = got.get(cid)
            where = f"{validator} {cid}"
            if entry is None:
                errors.append(f"{where}: no verdict")
                continue
            verdict = entry.get("verdict")
            if verdict not in VERDICTS:
                errors.append(f"{where}: verdict must be one of {sorted(VERDICTS)}")
                continue
            if verdict == "CONFIRMED":
                require_text(entry, [*FINDING_TEXT, "suggested_fix"], where, errors)
                if entry.get("severity") not in SEVERITIES:
                    errors.append(f"{where}: a CONFIRMED finding needs severity P0, P1 or P2")
                check_location(repo, entry.get("file"), entry.get("lines"), where, errors)
                evidence = entry.get("evidence")
                if not isinstance(evidence, list) or not evidence:
                    errors.append(f"{where}: CONFIRMED without evidence")
                else:
                    for item in evidence:
                        check_location(repo, item.get("file"), item.get("lines"), f"{where} evidence", errors)
                        if not str(item.get("fact", "")).strip():
                            errors.append(f"{where} evidence: missing fact")
                require_text(entry.get("checks") or {}, ["reachable", "guards", "callers_and_tests", "intentional"], f"{where} checks", errors)
                repro = entry.get("reproduction") or {}
                status = repro.get("status")
                if status not in REPRO_STATUSES:
                    errors.append(f"{where}: reproduction.status must be one of {sorted(REPRO_STATUSES)}")
                elif status == "reproduced":
                    require_text(repro, ["command", "result"], f"{where} reproduction", errors)
                else:
                    require_text(repro, ["why"], f"{where} reproduction", errors)
            elif verdict == "REJECTED":
                if entry.get("rejection_category") not in REJECTION_CATEGORIES:
                    errors.append(f"{where}: rejection_category must be one of {sorted(REJECTION_CATEGORIES)}")
                require_text(entry, ["reason"], where, errors)
            else:
                require_text(entry, ["missing_evidence"], where, errors)
            entry["_validator"] = validator
            per_claim[cid].append(entry)
    if errors:
        raise GateError(errors)
    return plan, {cid: merge_verdicts(cid, entries) for cid, entries in per_claim.items()}


def render_finding(f):
    repro = f["reproduction"]
    if repro["status"] == "reproduced":
        reproduction = f"Ran `{repro['command']}`. Result: {repro['result']}"
    elif repro["status"] == "not-reproduced":
        reproduction = f"Attempted, not demonstrated by execution: {repro['why']}"
    else:
        reproduction = f"Not executed: {repro['why']}"
        if repro.get("steps"):
            reproduction += f" Suggested steps: {repro['steps']}"
    evidence = "\n".join(f"  - `{e['file']}:{e['lines']}`: {e['fact']}" for e in f["evidence"])
    validators = ", ".join(f["validators"])
    return (
        f"### [{f['severity']}] {f['title']}\n\n"
        f"**Location:** `{f['file']}:{f['lines']}`\n\n"
        f"**Problem:** {f['actual']} Expected: {f['expected']} Root cause: {f['root_cause']}\n\n"
        f"**Trigger:** {f['trigger']}\n\n"
        f"**Impact:** {f['impact']}\n\n"
        f"**Evidence:**\n{evidence}\n\n"
        f"**Validation:** CONFIRMED by independent validation subagent {validators}.\n\n"
        f"**Reproduction:** {reproduction}\n\n"
        f"**Suggested fix:** {f['suggested_fix']}\n"
    )


def find_secrets(text):
    return [p.pattern for p in SECRET_PATTERNS if p.search(text)]


def cmd_report(args):
    work = Path(args.work).resolve()
    state = load_state(work)
    repo = Path(state["repo"])
    plan, results = collect_verdicts(work, repo)
    rows = read_ledger(work)
    errors = apply_coverage(work, rows)
    if errors:
        raise GateError(errors)
    write_ledger(work, rows)
    required, counts, modules, gaps = coverage_summary(rows)
    assigned_validators = sorted({v for vs in plan["assignment"].values() for v in vs})
    reviewers_done = [r for r in REVIEWERS if (work / f"review-{r}.json").exists()]

    confirmed = [r for r in results.values() if r["verdict"] == "CONFIRMED"]
    confirmed.sort(key=lambda r: (r["severity"], r["file"], span_start(r["lines"])))
    rejected = [r for r in results.values() if r["verdict"] == "REJECTED"]
    pending = [r for r in results.values() if r["verdict"] == "NEEDS_MORE_EVIDENCE"]
    sev = Counter(r["severity"] for r in confirmed)
    reviewed_files = sum(1 for r in required if r["status"] in ("full", "partial"))
    reviewed_modules = sum(1 for c in modules.values() if c["full"] or c["partial"])
    now = tree_fingerprint(repo)
    changed = bool(state["fingerprint"]) and now != state["fingerprint"]

    limits = []
    if gaps:
        limits.append(
            f"{len(gaps)} of {len(required)} required files were not fully reviewed "
            f"({counts['partial']} partial, {counts['skipped']} skipped, {counts['pending']} never reported)."
        )
    for rev, why in state.get("incomplete", {}).items():
        limits.append(f"Reviewer {rev} did not finish: {why}")
    if changed:
        limits.append("The working tree changed during the review (HEAD or `git status` differ from the start). Findings may refer to either state.")
    if state.get("scope"):
        limits.append(f"Scope was limited to: {', '.join(state['scope'])}.")
    limits.append("Per-file review status is reported by the reviewers and is not independently verified.")
    limit_text = "\n".join(f"  - {x}" for x in limits)

    out = [
        "# Deep Logic Review\n",
        "## Executive Summary\n",
        f"- **Review scope:** {{{{SCOPE}}}}",
        "- **Architecture overview:** {{ARCHITECTURE}}",
        f"- **Files and modules reviewed:** {reviewed_files} of {len(required)} required files, {reviewed_modules} of {len(modules)} modules ({counts['full']} files fully, {counts['partial']} partially)",
        f"- **Review subagents:** {len(reviewers_done)}",
        f"- **Independent validation subagents:** {len(assigned_validators)}" + (" (no candidates reached validation)" if not assigned_validators else ""),
        f"- **Confirmed P0:** {sev['P0']}",
        f"- **Confirmed P1:** {sev['P1']}",
        f"- **Confirmed P2:** {sev['P2']}",
        f"- **Coverage limitations:**\n{limit_text}\n",
        "## Confirmed Findings\n",
    ]
    if confirmed:
        out.extend(render_finding(f) for f in confirmed)
    else:
        out.append("No confirmed P0–P2 logic bugs were found in the reviewed scope.\n")

    out.append("## Rejected or Inconclusive Candidates\n")
    total = len(plan["assignment"])
    merged = len(plan["merged"])
    out.append(f"{total} unique candidates went to validation ({merged} duplicates merged first): {len(confirmed)} confirmed, {len(rejected)} rejected, {len(pending)} inconclusive. None of the items below are confirmed bugs.\n")
    if rejected:
        out.append("**Rejected, by category:**\n")
        cats = Counter(r["rejection_category"] for r in rejected)
        for cat, n in cats.most_common():
            out.append(f"- {REJECTION_CATEGORIES[cat]}: {n}")
        out.append("")
    if pending:
        out.append("**Inconclusive, with the evidence still missing:**\n")
        for r in pending:
            out.append(f"- {r.get('title', r['id'])}: {r['missing_evidence']}")
        out.append("")

    out.append("## Coverage Summary\n")
    out.append("| Module | Full | Partial | Skipped | Not reported |\n|---|---:|---:|---:|---:|")
    items = sorted(modules.items(), key=lambda kv: (-(sum(kv[1].values()) - kv[1]["full"]), kv[0]))
    for name, c in items[:30]:
        out.append(f"| `{name}` | {c['full']} | {c['partial']} | {c['skipped']} | {c['pending']} |")
    if len(items) > 30:
        out.append(f"\n{len(items) - 30} more modules, all in `ledger.tsv`.")
    reasons = Counter(r["note"].split(":")[0] for r in rows if r["category"] == "excluded")
    out.append("\n**Excluded:** " + (", ".join(f"{k} ({v})" for k, v in reasons.most_common()) or "nothing"))
    if state.get("reclass"):
        out.append("\n**Manual reclassifications:** " + "; ".join(f"`{x['glob']}` to {x['category']} ({x['reason']})" for x in state["reclass"]))
    out.append("\n{{COVERAGE_NOTES}}\n")
    out.append("## Final Assessment\n\n{{FINAL_ASSESSMENT}}\n")

    text = "\n".join(out)
    path = work / "report-skeleton.md"
    path.write_text(text)
    save_state(work, {**state, "expected": {s: sev[s] for s in SEVERITIES}})
    print(f"confirmed: P0={sev['P0']} P1={sev['P1']} P2={sev['P2']}; rejected={len(rejected)}; inconclusive={len(pending)}")
    print(f"required files: full={counts['full']} partial={counts['partial']} skipped={counts['skipped']} pending={counts['pending']}")
    if changed:
        print("WARNING: the working tree changed during the review. Check `git status` and report it to the user.")
    if find_secrets(text):
        print("WARNING: the skeleton matches a secret pattern. Mask it before finishing.")
    print(path)


def cmd_check_report(args):
    work = Path(args.work).resolve()
    state = load_state(work)
    expected = state.get("expected")
    if expected is None:
        raise GateError("run report first")
    text = Path(args.report).read_text()
    errors = []
    left = sorted(set(re.findall(r"\{\{[A-Z_]+\}\}", text)))
    if left:
        errors.append(f"unfilled placeholders: {left}")
    for sev in SEVERITIES:
        count = len(re.findall(rf"^#+\s*\[{sev}\]", text, re.M))
        if count != expected[sev]:
            errors.append(f"{sev}: report has {count} findings, validation confirmed {expected[sev]}")
    for pattern in find_secrets(text):
        errors.append(f"report matches secret pattern {pattern}; mask it")
    if not sum(expected.values()) and "No confirmed P0–P2 logic bugs were found in the reviewed scope." not in text:
        errors.append("a report with no findings must state the required no-findings sentence")
    if errors:
        raise GateError(errors)
    print("report passed the final gate")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    p.add_argument("repo")
    p.add_argument("--work", required=True)
    p.add_argument("--scope", action="append", default=[])
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)
    p = sub.add_parser("reclass")
    p.add_argument("work")
    p.add_argument("--glob", required=True)
    p.add_argument("--category", required=True)
    p.add_argument("--reason", required=True)
    p.set_defaults(func=cmd_reclass)
    p = sub.add_parser("assign")
    p.add_argument("work")
    p.add_argument("--map", required=True)
    p.set_defaults(func=cmd_assign)
    p = sub.add_parser("audit")
    p.add_argument("work")
    p.set_defaults(func=cmd_audit)
    p = sub.add_parser("candidates")
    p.add_argument("work")
    p.add_argument("--allow-incomplete", action="append", default=[], metavar="R1=reason")
    p.set_defaults(func=cmd_candidates)
    p = sub.add_parser("partition")
    p.add_argument("work")
    p.add_argument("--merge", action="append", default=[], metavar="KEEP:DUP")
    p.set_defaults(func=cmd_partition)
    p = sub.add_parser("sandbox")
    p.add_argument("work")
    p.add_argument("name")
    p.set_defaults(func=cmd_sandbox)
    p = sub.add_parser("report")
    p.add_argument("work")
    p.set_defaults(func=cmd_report)
    p = sub.add_parser("check-report")
    p.add_argument("work")
    p.add_argument("report")
    p.set_defaults(func=cmd_check_report)
    args = parser.parse_args()
    try:
        args.func(args)
    except GateError as exc:
        print("GATE FAILED:", file=sys.stderr)
        for error in exc.errors:
            print(f"  - {error}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
