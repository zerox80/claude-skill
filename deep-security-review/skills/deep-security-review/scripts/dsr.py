#!/usr/bin/env python3
"""Bookkeeping and phase gates for the deep-security-review plugin (stdlib only).

The model does the reviewing; this script keeps it honest about what the review
covered and blocks each phase until the previous one is really done. It never
writes to the repository, and it refuses a work directory inside it.

  init REPO --work DIR [--scope P]... [--language L]   inventory the repo, create ledger
  reclass WORK --glob G --category C --reason R        correct a classification
  plan WORK [--agents N]                               size the review (5-10 agents)
  suggest WORK                                         first-cut ownership map
  assign WORK --map MAP.json                           give every required file one owner
  brief WORK ID                                        print the full brief for one agent
  audit WORK                                           coverage from the reviewers' files
  candidates WORK [--allow-incomplete ID=why]          validate findings, assign IDs
  partition WORK [--merge KEEP:DUP]...                 write blinded claim sheets
  sandbox WORK NAME                                    disposable repo copy for test runs
  report WORK                                          validate verdicts, write skeleton
  check-report WORK REPORT.md                          final gate on the finished report
  status WORK                                          where the run stands, what is next

Exit codes: 0 ok, 2 the gate failed (the printed errors say what to fix).
"""
import argparse
import csv
import hashlib
import json
import math
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
REFS = SKILL_DIR / "references"

VALIDATORS = ["V1", "V2", "V3"]
SEVERITIES = ["P0", "P1", "P2"]
# How many of the three validators independently judge a claim of each severity.
REPLICATION = {"P0": 3, "P1": 2, "P2": 1}
MIN_AGENTS, MAX_AGENTS = 5, 10
MIN_SWEEPERS, MAX_SWEEPERS = 2, 3
LINES_PER_OWNER = 30000
# Default lens groups per sweeper count. A sweeper may carry several lenses; each lens is used at most once.
SWEEPER_GROUPS = {
    2: [["authz", "logic-abuse", "crypto-secrets"], ["injection", "ssrf-files", "web-client", "config-cicd"]],
    3: [["authz", "logic-abuse"], ["injection", "ssrf-files", "config-cicd"], ["web-client", "crypto-secrets"]],
}

LEDGER_FIELDS = ["path", "category", "lines", "required", "owner", "status", "note"]
COVERAGE_STATUSES = {"full", "partial", "skipped"}
VERDICTS = {"CONFIRMED", "REJECTED", "NEEDS_MORE_EVIDENCE"}
REPRO_STATUSES = {"reproduced", "not-reproduced", "not-attempted"}
VULN_CATEGORIES = {
    "authn", "authz", "injection", "ssrf", "path-traversal", "file-handling", "deserialization",
    "xss", "csrf", "open-redirect", "crypto", "session-token", "secrets", "race-condition",
    "logic", "info-disclosure", "xxe", "config", "cicd", "dependency", "other",
}
REJECTION_CATEGORIES = {
    "unreachable": {
        "en": "The path cannot occur in real execution",
        "de": "Der Pfad kann in der echten Ausführung nicht auftreten",
    },
    "guarded": {
        "en": "An existing guard or protection already stops it",
        "de": "Eine vorhandene Schutzmaßnahme verhindert es bereits",
    },
    "intended": {
        "en": "The behavior is intentional or documented",
        "de": "Das Verhalten ist beabsichtigt oder dokumentiert",
    },
    "not-attacker-controlled": {
        "en": "The input is not controllable by an attacker under the threat model",
        "de": "Die Eingabe ist unter dem Bedrohungsmodell nicht vom Angreifer kontrollierbar",
    },
    "trusted-actor": {
        "en": "It needs a trusted actor (for example an administrator) to attack themselves",
        "de": "Es setzt einen vertrauenswürdigen Akteur (z. B. Administrator) voraus, der sich selbst angreift",
    },
    "excluded-class": {
        "en": "It belongs to a class that is out of scope (hardening, DoS, theoretical)",
        "de": "Es gehört zu einer Klasse außerhalb des Umfangs (Hardening, DoS, theoretisch)",
    },
    "below-threshold": {
        "en": "Real, but below P2",
        "de": "Real, aber unterhalb von P2",
    },
    "speculative": {
        "en": "The claim rests on unsupported assumptions",
        "de": "Die Behauptung beruht auf nicht belegten Annahmen",
    },
    "misread-code": {
        "en": "The code does not behave as the claim describes",
        "de": "Der Code verhält sich nicht wie behauptet",
    },
    "other": {"en": "Other", "de": "Sonstiges"},
}
REQUIRED_CATEGORIES = {"source", "config", "schema"}
CATEGORIES = REQUIRED_CATEGORIES | {"test", "docs", "other", "excluded"}

VENDOR_DIRS = {
    "node_modules", "vendor", "vendored", "third_party", "thirdparty", "third-party",
    "3rdparty", "bower_components", "dist", "build", "target", "out", ".next", ".nuxt",
    "__pycache__", ".venv", "venv", ".tox", ".gradle", ".idea", ".vscode", ".git",
    "coverage", ".cache", ".terraform", "pods",
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
    "j2", "hbs", "tf", "cairo", "move", "wat", "asm", "s", "ui", "twig", "phtml", "jsp", "asp",
    "aspx", "cshtml", "razor", "mustache", "pug",
}
CONFIG_EXT = {
    "yml", "yaml", "toml", "ini", "cfg", "conf", "properties", "cmake", "gradle", "xml",
    "json", "json5", "plist", "tfvars", "editorconfig", "in", "mk", "nix", "bzl", "pro", "pri",
    "htaccess",
}
CONFIG_NAMES = {
    "makefile", "dockerfile", "jenkinsfile", "cmakelists.txt", "justfile", "rakefile",
    "gemfile", "procfile", "vagrantfile", "build", "workspace", "containerfile", "brewfile",
    ".htaccess",
}
SCHEMA_EXT = {"sql", "prisma", "graphql", "gql", "proto", "avsc", "thrift", "xsd", "edmx"}
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
SECRET_PATTERNS = {
    "aws-access-key": r"AKIA[0-9A-Z]{16}",
    "aws-temp-key": r"ASIA[0-9A-Z]{16}",
    "github-token": r"gh[pousr]_[A-Za-z0-9]{30,}",
    "github-pat": r"github_pat_[A-Za-z0-9_]{30,}",
    "gitlab-token": r"glpat-[A-Za-z0-9_-]{16,}",
    "slack-token": r"xox[abpsr]-[A-Za-z0-9-]{10,}",
    "api-key-sk": r"sk-[A-Za-z0-9_-]{24,}",
    "google-api-key": r"AIza[0-9A-Za-z_-]{30,}",
    "private-key-block": r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    "jwt": r"eyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}",
}
SECRET_REGEX = {name: re.compile(p) for name, p in SECRET_PATTERNS.items()}

STRINGS = {
    "en": {
        "title": "Deep Security Review",
        "summary": "Executive Summary",
        "scope": "Review scope",
        "arch": "Architecture and attack surface",
        "files": "Files and modules reviewed",
        "files_fmt": "{rf} of {rq} required files, {rm} of {tm} modules ({full} files fully, {part} partially)",
        "agents": "Review subagents",
        "agents_fmt": "{n} ({o} component owners, {s} cross-cutting sweepers)",
        "validators": "Independent validation subagents",
        "validators_none": " (no candidates reached validation)",
        "confirmed": "Confirmed",
        "limits": "Coverage limitations",
        "findings": "Confirmed Findings",
        "no_findings": "No confirmed P0–P2 security vulnerabilities were found in the reviewed scope.",
        "location": "Location",
        "category": "Category",
        "attacker": "Attacker and preconditions",
        "vuln": "Vulnerability",
        "exploit": "Exploit scenario",
        "impact": "Impact",
        "evidence": "Evidence",
        "validation": "Validation",
        "validation_fmt": "CONFIRMED by {n} independent validation subagent(s): {v}.",
        "repro": "Reproduction",
        "repro_ran": "Ran `{command}`. Result: {result}",
        "repro_not": "Attempted, not demonstrated by execution: {why}",
        "repro_none": "Not executed: {why}",
        "repro_steps": " Suggested steps: {steps}",
        "fix": "Suggested fix",
        "expected": "Expected",
        "root_cause": "Root cause",
        "rejected": "Rejected or Inconclusive Candidates",
        "rejected_fmt": (
            "{total} unique candidates went to validation ({merged} duplicates merged first): "
            "{c} confirmed, {r} rejected, {p} inconclusive. None of the items below are confirmed vulnerabilities.\n"
        ),
        "rejected_by": "**Rejected, by category:**\n",
        "inconclusive": "**Inconclusive, with the evidence still missing:**\n",
        "coverage": "Coverage Summary",
        "module": "Module",
        "full": "Full",
        "partial": "Partial",
        "skipped": "Skipped",
        "pending": "Not reported",
        "more_modules": "{n} more modules, all in `ledger.tsv`.",
        "excluded": "Excluded",
        "nothing": "nothing",
        "reclass": "Manual reclassifications",
        "notes": "Notes",
        "assessment": "Final Assessment",
        "lim_gaps": "{g} of {r} required files were not fully reviewed ({p} partial, {s} skipped, {n} never reported).",
        "lim_incomplete": "Agent {a} did not finish: {why}",
        "lim_changed": "The working tree changed during the review (HEAD or `git status` differ from the start). Findings may refer to either state.",
        "lim_scope": "Scope was limited to: {s}.",
        "lim_unverified": "Per-file review status is reported by the reviewers and is not independently verified.",
        "note_sensitive": "{n} secret-like files are part of the repository and were deliberately not opened: {files}. Check them manually.",
        "note_leads": "{n} secret-pattern matches were found by a text scan (locations only, see `secret-leads.tsv`); the secrets sweeper triaged them.",
        "note_none": "No secret-like files and no secret-pattern matches were found by the inventory scan.",
    },
    "de": {
        "title": "Deep Security Review",
        "summary": "Zusammenfassung",
        "scope": "Prüfumfang",
        "arch": "Architektur und Angriffsfläche",
        "files": "Geprüfte Dateien und Module",
        "files_fmt": "{rf} von {rq} erforderlichen Dateien, {rm} von {tm} Modulen ({full} Dateien vollständig, {part} teilweise)",
        "agents": "Review-Subagents",
        "agents_fmt": "{n} ({o} Komponenten-Owner, {s} übergreifende Sweeper)",
        "validators": "Unabhängige Validierungs-Subagents",
        "validators_none": " (kein Kandidat erreichte die Validierung)",
        "confirmed": "Bestätigte",
        "limits": "Einschränkungen der Abdeckung",
        "findings": "Bestätigte Findings",
        "no_findings": "Im geprüften Umfang wurden keine bestätigten P0–P2-Sicherheitslücken gefunden.",
        "location": "Fundstelle",
        "category": "Kategorie",
        "attacker": "Angreifer und Voraussetzungen",
        "vuln": "Schwachstelle",
        "exploit": "Angriffsszenario",
        "impact": "Auswirkung",
        "evidence": "Belege",
        "validation": "Validierung",
        "validation_fmt": "BESTÄTIGT durch {n} unabhängige(n) Validierungs-Subagent(s): {v}.",
        "repro": "Reproduktion",
        "repro_ran": "Ausgeführt: `{command}`. Ergebnis: {result}",
        "repro_not": "Versucht, aber nicht per Ausführung nachgewiesen: {why}",
        "repro_none": "Nicht ausgeführt: {why}",
        "repro_steps": " Vorgeschlagene Schritte: {steps}",
        "fix": "Fix-Vorschlag",
        "expected": "Erwartet",
        "root_cause": "Ursache",
        "rejected": "Verworfene oder unklare Kandidaten",
        "rejected_fmt": (
            "{total} eindeutige Kandidaten gingen in die Validierung ({merged} Duplikate vorher zusammengeführt): "
            "{c} bestätigt, {r} verworfen, {p} unklar. Keiner der folgenden Punkte ist eine bestätigte Schwachstelle.\n"
        ),
        "rejected_by": "**Verworfen, nach Kategorie:**\n",
        "inconclusive": "**Unklar, es fehlt noch Evidenz:**\n",
        "coverage": "Abdeckung",
        "module": "Modul",
        "full": "Vollständig",
        "partial": "Teilweise",
        "skipped": "Übersprungen",
        "pending": "Nicht gemeldet",
        "more_modules": "{n} weitere Module, alle in `ledger.tsv`.",
        "excluded": "Ausgeschlossen",
        "nothing": "nichts",
        "reclass": "Manuelle Neuklassifizierungen",
        "notes": "Hinweise",
        "assessment": "Gesamtbewertung",
        "lim_gaps": "{g} von {r} erforderlichen Dateien wurden nicht vollständig geprüft ({p} teilweise, {s} übersprungen, {n} nie gemeldet).",
        "lim_incomplete": "Agent {a} wurde nicht fertig: {why}",
        "lim_changed": "Der Working Tree hat sich während des Reviews geändert (HEAD oder `git status` weichen vom Start ab). Findings können sich auf beide Stände beziehen.",
        "lim_scope": "Der Umfang war begrenzt auf: {s}.",
        "lim_unverified": "Der Prüfstatus pro Datei wird von den Reviewern gemeldet und nicht unabhängig verifiziert.",
        "note_sensitive": "{n} geheimnisähnliche Dateien liegen im Repository und wurden bewusst nicht geöffnet: {files}. Bitte manuell prüfen.",
        "note_leads": "Ein Textscan fand {n} Treffer auf Secret-Muster (nur Fundstellen, siehe `secret-leads.tsv`); der Secrets-Sweeper hat sie triagiert.",
        "note_none": "Der Inventar-Scan fand weder geheimnisähnliche Dateien noch Treffer auf Secret-Muster.",
    },
}


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
    import os

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
    hit = next((d for d in dirs if d.lower() in VENDOR_DIRS), None)
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


def find_secrets(text):
    return [name for name, rx in SECRET_REGEX.items() if rx.search(text)]


def report_lang(state):
    language = str(state.get("language", "English")).strip().lower()
    return "de" if re.match(r"(german|deutsch|de\b)", language) else "en"


def load_lenses():
    """Single source of truth: '## key — Title' sections of references/sweeper-lenses.md."""
    path = REFS / "sweeper-lenses.md"
    if not path.exists():
        raise GateError(f"missing {path}")
    text = path.read_text(encoding="utf-8")
    lenses = {}
    for m in re.finditer(r"^##\s+([a-z0-9-]+)\s+—\s+(.+?)\n(.*?)(?=^## |\Z)", text, re.S | re.M):
        lenses[m.group(1)] = (m.group(2).strip(), m.group(3).strip())
    if not lenses:
        raise GateError(f"{path} defines no lenses")
    return lenses


def agent_ids(state, kind=None):
    agents = state.get("agents", {})
    return sorted(a for a, meta in agents.items() if kind is None or meta["kind"] == kind)


# --- init / reclass --------------------------------------------------------


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

    sensitive = [r["path"] for r in rows if r["note"] == "sensitive"]
    (work / "sensitive-files.txt").write_text("".join(f"{p}\n" for p in sensitive))
    leads = scan_secret_leads(repo, rows)
    with open(work / "secret-leads.tsv", "w", encoding="utf-8") as fh:
        fh.write("path\tline\tkind\n")
        fh.writelines(f"{p}\t{n}\t{k}\n" for p, n, k in leads)

    save_state(work, {
        "repo": str(repo),
        "scope": args.scope,
        "language": args.language,
        "fingerprint": tree_fingerprint(repo),
        "nested_in_git_root": nested,
        "reclass": [],
        "incomplete": {},
        "sensitive_files": sensitive,
        "secret_leads": len(leads),
    })
    print_inventory(rows, repo, work, sensitive, leads)


def scan_secret_leads(repo, rows):
    """Pattern hits as (path, line, kind). Values are never stored or printed."""
    leads = []
    for row in rows:
        if row["category"] == "excluded" or not row["lines"]:
            continue
        path = Path(repo) / row["path"]
        try:
            if path.stat().st_size > 2_000_000:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for kind, rx in SECRET_REGEX.items():
            for m in rx.finditer(text):
                leads.append((row["path"], text.count("\n", 0, m.start()) + 1, kind))
    return sorted(set(leads))


def print_inventory(rows, repo, work, sensitive, leads):
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
    print("\nexcluded, by reason (check for application-owned code, then reclass):")
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
    print(f"\nsecret-like files in the repo (never opened): {len(sensitive)}" + (f", e.g. {sensitive[:5]}" if sensitive else ""))
    print(f"secret-pattern text matches (locations only, secret-leads.tsv): {len(leads)}")


def cmd_reclass(args):
    work = Path(args.work).resolve()
    state = load_state(work)
    if args.category not in CATEGORIES:
        raise GateError(f"category must be one of {sorted(CATEGORIES)}")
    if (work / "assignment.json").exists():
        raise GateError("agents are already assigned. Reclassify before assign, then rerun plan and assign.")
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
    state.pop("plan", None)
    write_ledger(work, rows)
    save_state(work, state)
    print(f"reclassified {changed} files as {args.category}; rerun plan")


# --- plan / suggest / assign -----------------------------------------------


def cmd_plan(args):
    work = Path(args.work).resolve()
    state = load_state(work)
    required = [r for r in read_ledger(work) if r["required"] == "yes"]
    files, lines = len(required), sum(r["lines"] for r in required)
    if not files:
        raise GateError("no required files. Check the scope and the exclusions in the inventory.")
    small = files + MIN_SWEEPERS < MIN_AGENTS
    min_agents = files + MIN_SWEEPERS if small else MIN_AGENTS
    wanted = args.agents or math.ceil(lines / LINES_PER_OWNER / 0.7)
    total = max(min_agents, min(MAX_AGENTS, wanted))
    sweepers = max(MIN_SWEEPERS, min(MAX_SWEEPERS, round(total * 0.3)))
    owners = total - sweepers
    if owners > files:
        owners = files
        total = max(owners + sweepers, min_agents)
        sweepers = total - owners
    plan = {"min_agents": min_agents, "total": total, "owners": owners, "sweepers": sweepers, "small": small}
    state["plan"] = plan
    save_state(work, state)
    lenses = load_lenses()
    print(f"required: {files} files, {lines} lines")
    print(f"agents: {total} = {owners} component owners (R01-R{owners:02d}) + {sweepers} sweepers (S1-S{sweepers})")
    print(f"allowed range: {min_agents}-{MAX_AGENTS} agents, {MIN_SWEEPERS}-{MAX_SWEEPERS} sweepers")
    print(f"~{lines // owners} lines per owner")
    if small:
        print(f"NOTE: the repo is too small for {MIN_AGENTS} agents with real work; minimum lowered to {min_agents}. Disclose this in the report.")
    if args.agents and args.agents != total:
        print(f"NOTE: --agents {args.agents} was adjusted to {total} (allowed range {min_agents}-{MAX_AGENTS}).")
    if lines / owners > 50000:
        print("WARNING: owners cannot read this much in depth. Tell each owner which modules to read in full (by risk) and accept partial coverage for the rest; it will show in the report. A narrower --scope is the cheaper fix.")
    print("\nsweeper lenses (a sweeper may carry several):")
    for key, (title, _) in lenses.items():
        print(f"  {key}: {title}")
    print(f"\nnext: suggest {work}   (or write your own map and run assign)")


def make_units(files, prefix, target, out):
    """Split a directory tree into units of roughly `target` lines, keeping directories whole where they fit."""
    total = sum(n for _, n in files)
    if total <= target:
        out.append({"globs": [prefix or "**"], "lines": total, "files": list(files)})
        return
    plen = len(prefix) + 1 if prefix else 0
    subdirs, direct = defaultdict(list), []
    for path, n in files:
        rest = path[plen:]
        if "/" in rest:
            subdirs[rest.split("/", 1)[0]].append((path, n))
        else:
            direct.append((path, n))
    for name in sorted(subdirs):
        make_units(subdirs[name], f"{prefix}/{name}" if prefix else name, target, out)
    chunk, acc = [], 0
    for path, n in sorted(direct):
        if chunk and acc + n > target:
            out.append({"globs": [p for p, _ in chunk], "lines": acc, "files": chunk})
            chunk, acc = [], 0
        chunk.append((path, n))
        acc += n
    if chunk:
        out.append({"globs": [p for p, _ in chunk], "lines": acc, "files": chunk})


def pack_units(units, n):
    total = sum(u["lines"] for u in units) or 1
    bins = [[] for _ in range(n)]
    cum = 0
    for u in units:
        mid = cum + u["lines"] / 2
        bins[min(n - 1, int(mid * n / total))].append(u)
        cum += u["lines"]
    if all(bins):
        return bins
    bins = [[] for _ in range(n)]
    load = [0] * n
    for u in sorted(units, key=lambda x: -x["lines"]):
        i = min(range(n), key=lambda k: (bool(bins[k]), load[k], k))
        bins[i].append(u)
        load[i] += u["lines"]
    return bins


def unit_area(unit):
    """Short label for a unit: its directory glob, or the directory of its exact file paths."""
    first = unit["globs"][0]
    if first in {p for p, _ in unit["files"]}:
        return first.rsplit("/", 1)[0] if "/" in first else "(root)"
    return first


def cmd_suggest(args):
    work = Path(args.work).resolve()
    state = load_state(work)
    plan = state.get("plan")
    if not plan:
        raise GateError("run plan first")
    required = [r for r in read_ledger(work) if r["required"] == "yes"]
    owners = plan["owners"]
    total = sum(r["lines"] for r in required)
    files = sorted((r["path"], r["lines"]) for r in required)
    units = []
    make_units(files, "", max(1.0, total / owners), units)
    while len(units) < owners:
        splittable = [u for u in units if len(u["files"]) > 1]
        if not splittable:
            break
        big = max(splittable, key=lambda u: len(u["files"]))
        i = units.index(big)
        units[i:i + 1] = [{"globs": [p], "lines": n, "files": [(p, n)]} for p, n in big["files"]]
    bins = pack_units(units, owners)
    owner_map = {f"R{i + 1:02d}": [g for u in b for g in u["globs"]] for i, b in enumerate(bins)}
    lenses = load_lenses()
    groups = SWEEPER_GROUPS[min(max(plan["sweepers"], MIN_SWEEPERS), MAX_SWEEPERS)][:plan["sweepers"]]
    sweeper_map = {f"S{i + 1}": [k for k in g if k in lenses] for i, g in enumerate(groups)}
    out = work / "map.suggested.json"
    out.write_text(json.dumps({"owners": owner_map, "sweepers": sweeper_map}, indent=2))
    print("owner      lines  files  main areas")
    for i, b in enumerate(bins):
        areas = ", ".join(dict.fromkeys(unit_area(u) for u in b))
        print(f"R{i + 1:02d}   {sum(u['lines'] for u in b):9} {sum(len(u['files']) for u in b):6}  {areas[:110]}")
    print("sweepers: " + ", ".join(f"{k}={'+'.join(v)}" for k, v in sweeper_map.items()))
    print(f"\n{out}\nAdjust by architecture if you can (a leading '!' in an owner's glob list excludes matches from that owner), then run assign.")


def cmd_assign(args):
    work = Path(args.work).resolve()
    state = load_state(work)
    plan = state.get("plan")
    if not plan:
        raise GateError("run plan first")
    mapping = load_json(args.map)
    owners_map = mapping.get("owners") or {}
    sweepers_map = mapping.get("sweepers") or {}
    lenses = load_lenses()
    errors = []
    for oid, globs in owners_map.items():
        if not re.fullmatch(r"R\d{2}", oid):
            errors.append(f"owner id {oid!r} must look like R01")
        if not isinstance(globs, list) or not all(isinstance(g, str) for g in globs):
            errors.append(f"{oid}: needs a list of glob strings")
    sweepers_map = {sid: ([v] if isinstance(v, str) else v) for sid, v in sweepers_map.items()}
    used = Counter()
    for sid, keys in sweepers_map.items():
        if not re.fullmatch(r"S\d", sid):
            errors.append(f"sweeper id {sid!r} must look like S1")
        if not isinstance(keys, list) or not keys:
            errors.append(f"{sid}: needs one or more lenses")
            continue
        for lens in keys:
            if lens not in lenses:
                errors.append(f"{sid}: unknown lens {lens!r}; use one of {sorted(lenses)}")
            used[lens] += 1
    errors.extend(f"lens {lens!r} is assigned to more than one sweeper" for lens, n in used.items() if n > 1)
    total = len(owners_map) + len(sweepers_map)
    if not MIN_SWEEPERS <= len(sweepers_map) <= MAX_SWEEPERS:
        errors.append(f"{len(sweepers_map)} sweepers; need {MIN_SWEEPERS}-{MAX_SWEEPERS}")
    if not plan["min_agents"] <= total <= MAX_AGENTS:
        errors.append(f"{total} agents in total; the allowed range for this repo is {plan['min_agents']}-{MAX_AGENTS}")
    if errors:
        raise GateError(errors)

    compiled = {
        oid: ([glob_regex(g) for g in globs if not g.startswith("!")], [glob_regex(g[1:]) for g in globs if g.startswith("!")])
        for oid, globs in owners_map.items()
    }
    rows = read_ledger(work)
    required = [r for r in rows if r["required"] == "yes"]
    unassigned, overlap = [], []
    for row in rows:
        row["owner"] = "-"
    for row in required:
        hits = [o for o, (inc, exc) in compiled.items() if any(p.match(row["path"]) for p in inc) and not any(p.match(row["path"]) for p in exc)]
        if len(hits) > 1:
            overlap.append(f"{row['path']} -> {hits}")
        elif not hits:
            unassigned.append(row["path"])
        else:
            row["owner"] = hits[0]
    if overlap:
        errors.append(f"{len(overlap)} files have more than one owner, e.g. {overlap[:15]}")
    if unassigned:
        errors.append(f"{len(unassigned)} required files have no owner, e.g. {unassigned[:30]}")
    empty = [o for o in owners_map if not any(r["owner"] == o for r in required)]
    if empty:
        errors.append(f"owners without any file: {empty}; merge or drop them")
    if errors:
        raise GateError(errors)

    write_ledger(work, rows)
    (work / "assignment.json").write_text(json.dumps(mapping, indent=2))
    state["agents"] = {
        **{o: {"kind": "owner"} for o in sorted(owners_map)},
        **{s: {"kind": "sweeper", "lenses": keys} for s, keys in sorted(sweepers_map.items())},
    }
    save_state(work, state)
    for oid in sorted(owners_map):
        owned = [r for r in required if r["owner"] == oid]
        (work / f"scope-{oid}.txt").write_text("".join(f"{r['lines']}\t{r['path']}\n" for r in owned))
        print(f"{oid}: {len(owned)} files, {sum(r['lines'] for r in owned)} lines")
    for sid, keys in sorted(sweepers_map.items()):
        print(f"{sid}: sweeper, lenses {', '.join(keys)}")
    print(f"\n{total} agents assigned. Optional per-agent hints go to {work}/notes-<ID>.md. Launch them with the short prompt from SKILL.md.")


# --- briefs ----------------------------------------------------------------


def cmd_brief(args):
    work = Path(args.work).resolve()
    state = load_state(work)
    aid = args.id
    repo = state["repo"]
    notes_path = work / f"notes-{aid}.md"
    notes = notes_path.read_text() if notes_path.exists() else "none"
    subs = {
        "ID": aid,
        "REPO": repo,
        "WORK": str(work),
        "SKILL": str(SKILL_DIR),
        "LANGUAGE": state.get("language", "English"),
        "NOTES": notes.strip() or "none",
    }
    if aid in VALIDATORS:
        template, blocks = REFS / "validator-brief.md", [aid]
        sheet = work / f"claims-{aid}.json"
        if not sheet.exists():
            raise GateError(f"{sheet.name} does not exist; run partition first")
        subs["CLAIMS_FILE"] = str(sheet)
        subs["CLAIM_COUNT"] = str(len(json.loads(sheet.read_text())))
    elif aid in state.get("agents", {}):
        meta = state["agents"][aid]
        template, blocks = REFS / "reviewer-brief.md", [meta["kind"]]
        if meta["kind"] == "owner":
            scope = work / f"scope-{aid}.txt"
            entries = [line for line in scope.read_text().splitlines() if line]
            subs["SCOPE_FILE"] = str(scope)
            subs["SCOPE_SUMMARY"] = f"{len(entries)} files, {sum(int(e.split(chr(9))[0]) for e in entries)} lines"
        else:
            catalog = load_lenses()
            subs["LENS_KEY"] = ", ".join(meta["lenses"])
            subs["LENS_TITLE"] = "; ".join(catalog[k][0] for k in meta["lenses"])
            subs["LENS"] = "\n\n".join(f"### {k}: {catalog[k][0]}\n\n{catalog[k][1]}" for k in meta["lenses"])
    else:
        raise GateError(f"unknown agent id {aid!r}; known: {agent_ids(state) + VALIDATORS}")

    text = template.read_text(encoding="utf-8")
    text = re.sub(r"<!-- (\w+):begin -->\n(.*?)<!-- \1:end -->\n", lambda m: m.group(2) if m.group(1) in blocks else "", text, flags=re.S)
    for key, value in subs.items():
        text = text.replace("{{" + key + "}}", value)
    left = sorted(set(re.findall(r"\{\{[A-Z_]+\}\}", text)) - {"{{RUBRIC}}"})
    if left:
        raise GateError(f"brief template has unfilled placeholders: {left}")
    rubric = (REFS / "severity-and-scope.md").read_text(encoding="utf-8")
    print(text.replace("{{RUBRIC}}", rubric))


# --- coverage --------------------------------------------------------------


def apply_coverage(work, rows, owners):
    """Recompute ledger status. Only the owner's report can mark a file reviewed."""
    errors = []
    for row in rows:
        if row["required"] == "yes":
            row["status"], row["note"] = "pending", ""
    by_path = {r["path"]: r for r in rows}
    for rev in owners:
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
    state = load_state(work)
    if not state.get("agents"):
        raise GateError("run assign first")
    owners = agent_ids(state, "owner")
    rows = read_ledger(work)
    errors = apply_coverage(work, rows, owners)
    if errors:
        raise GateError(errors)
    write_ledger(work, rows)
    required, counts, modules, gaps = coverage_summary(rows)
    unfinished = []
    for aid in agent_ids(state):
        path = work / f"review-{aid}.json"
        if not path.exists():
            unfinished.append(f"{aid}: no review file yet")
            continue
        try:
            complete = json.loads(path.read_text()).get("complete")
        except json.JSONDecodeError:
            unfinished.append(f"{aid}: review file is not valid JSON")
            continue
        if complete is not True:
            unfinished.append(f"{aid}: complete={complete}")
    print(f"agents finished: {len(state['agents']) - len(unfinished)} of {len(state['agents'])}")
    for line in unfinished:
        print(f"  {line}")
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


# --- candidates ------------------------------------------------------------

FINDING_TEXT = ["title", "attacker", "preconditions", "source", "root_cause", "exploit_scenario", "impact", "protections_checked"]


def validate_finding(repo, finding, where, errors):
    require_text(finding, FINDING_TEXT, where, errors)
    if finding.get("severity") not in SEVERITIES:
        errors.append(f"{where}: severity must be P0, P1 or P2, got {finding.get('severity')!r}")
    if finding.get("category") not in VULN_CATEGORIES:
        errors.append(f"{where}: category must be one of {sorted(VULN_CATEGORIES)}, got {finding.get('category')!r}")
    check_location(repo, finding.get("file"), finding.get("lines"), where, errors)
    steps = finding.get("data_flow")
    if not isinstance(steps, list) or not steps:
        errors.append(f"{where}: data_flow must list the path from attacker input to the vulnerable operation")
    else:
        for step in steps:
            check_location(repo, step.get("file"), step.get("lines"), f"{where} data_flow step", errors)


def cmd_candidates(args):
    work = Path(args.work).resolve()
    state = load_state(work)
    repo = Path(state["repo"])
    if not state.get("agents"):
        raise GateError("run assign first")
    incomplete = dict(a.split("=", 1) for a in args.allow_incomplete)
    errors, findings = [], []
    for aid in agent_ids(state):
        path = work / f"review-{aid}.json"
        if not path.exists():
            if aid not in incomplete:
                errors.append(f"{aid}: review file is missing; the review phase is not finished")
            continue
        data = load_json(path)
        if data.get("complete") is not True and aid not in incomplete:
            errors.append(f"{aid}: complete is not true; finish it, or pass --allow-incomplete {aid}=reason")
        if state["agents"][aid]["kind"] == "sweeper" and data.get("complete") is True:
            swept = data.get("swept")
            if not isinstance(swept, list) or not any(isinstance(s, str) and s.strip() for s in swept):
                errors.append(f"{aid}: a finished sweeper must list what it enumerated in 'swept'")
        for i, finding in enumerate(data.get("findings", []), 1):
            validate_finding(repo, finding, f"{aid} finding {i}", errors)
            finding["reviewer"] = aid
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
        print(f"  {f['id']} {f['severity']} {f['reviewer']:3} {f['category']:15} {f['file']}:{f['lines']}  {f['title']}")
    print("\npossible duplicates (same file, overlapping or adjacent lines, or same title):")
    any_dup = False
    for i, a in enumerate(findings):
        for b in findings[i + 1:]:
            near = a["file"] == b["file"] and span_start(b["lines"]) <= span_end(a["lines"]) + 5 and span_start(a["lines"]) <= span_end(b["lines"]) + 5
            if near or a["title"].strip().lower() == b["title"].strip().lower():
                print(f"  {a['id']} / {b['id']}")
                any_dup = True
    if not any_dup:
        print("  none")


def partition_claims(claims):
    """Each claim goes to REPLICATION[severity] validators; same-file claims prefer the same validator."""
    buckets = {v: [] for v in VALIDATORS}
    if not claims:
        return buckets
    load = Counter()
    seen = {v: set() for v in VALIDATORS}
    order = sorted(claims, key=lambda c: (c["claimed_severity"], -c["_weight"], c["id"]))
    for claim in order:
        ranked = sorted(VALIDATORS, key=lambda v: (load[v] - (2 if claim["file"] in seen[v] else 0), v))
        for v in ranked[:REPLICATION[claim["claimed_severity"]]]:
            buckets[v].append(claim)
            load[v] += claim["_weight"]
            seen[v].add(claim["file"])
    for v in VALIDATORS:
        if not buckets[v]:
            buckets[v].append(order[0])
    for v in VALIDATORS:
        buckets[v].sort(key=lambda c: (c["claimed_severity"], c["id"]))
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
        elif dup in merged.values() or keep in merged:
            errors.append(f"bad merge {pair!r}; merges must not chain")
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
        # The sheet is blinded: no reviewer identity, data flow, protections or reasoning.
        claims.append({
            "id": cand["id"],
            "claimed_severity": min(severities),
            "title": cand["title"],
            "category": cand["category"],
            "file": cand["file"],
            "lines": cand["lines"],
            "also_reported_at": [f"{d['file']}:{d['lines']}" for d in dups],
            "claimed_attacker": cand["attacker"],
            "claimed_preconditions": cand["preconditions"],
            "claimed_source": cand["source"],
            "claimed_exploit_scenario": cand["exploit_scenario"],
            "claimed_impact": cand["impact"],
            "assumptions_to_check": cand.get("assumptions", []),
            "_weight": 2 + len(cand.get("data_flow", [])) + len(dups),
        })
    buckets = partition_claims(claims)
    assignment = {}
    for validator, items in buckets.items():
        for claim in items:
            assignment.setdefault(claim["id"], []).append(validator)
        sheet = [{k: v for k, v in c.items() if not k.startswith("_")} for c in items]
        (work / f"claims-{validator}.json").write_text(json.dumps(sheet, indent=2))
    (work / "validation-assignment.json").write_text(json.dumps({"merged": merged, "assignment": assignment}, indent=2))
    print(f"unique claims: {len(claims)} (merged {len(merged)})")
    print("replication: P0 -> all 3 validators, P1 -> 2 validators, P2 -> 1 validator; every assigned validator must confirm")
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
    skip = {"sensitive", "submodule-or-missing", "translations", "binary-or-asset", "binary", "symlink", "unreadable"}
    copied = 0
    for row in read_ledger(work):
        if row["note"] in skip:
            continue
        src, target = repo / row["path"], dest / row["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, target, follow_symlinks=False)
            copied += 1
        except OSError:
            continue
    print(dest)
    print(f"copied {copied} files; secret-like files, assets and translations were left out; dependencies are not included", file=sys.stderr)


# --- verdicts and report ---------------------------------------------------


def merge_verdicts(cid, entries):
    """All assigned validators must confirm; severity takes the lowest confirmed rating."""
    verdicts = {e["verdict"] for e in entries}
    if verdicts == {"CONFIRMED"}:
        chosen = max(entries, key=lambda e: e["severity"])
        return {**chosen, "id": cid, "validators": sorted(e["_validator"] for e in entries)}
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
                require_text(entry, [*FINDING_TEXT[:2], "preconditions", "root_cause", "exploit_scenario", "impact", "suggested_fix"], where, errors)
                if entry.get("severity") not in SEVERITIES:
                    errors.append(f"{where}: a CONFIRMED finding needs severity P0, P1 or P2")
                if entry.get("category") not in VULN_CATEGORIES:
                    errors.append(f"{where}: a CONFIRMED finding needs a category from {sorted(VULN_CATEGORIES)}")
                check_location(repo, entry.get("file"), entry.get("lines"), where, errors)
                evidence = entry.get("evidence")
                if not isinstance(evidence, list) or not evidence:
                    errors.append(f"{where}: CONFIRMED without evidence")
                else:
                    for item in evidence:
                        check_location(repo, item.get("file"), item.get("lines"), f"{where} evidence", errors)
                        if not str(item.get("fact", "")).strip():
                            errors.append(f"{where} evidence: missing fact")
                require_text(entry.get("checks") or {}, ["reachable", "attacker_control", "guards", "callers_and_tests", "intentional"], f"{where} checks", errors)
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


def render_finding(f, t):
    repro = f["reproduction"]
    if repro["status"] == "reproduced":
        reproduction = t["repro_ran"].format(command=repro["command"], result=repro["result"])
    elif repro["status"] == "not-reproduced":
        reproduction = t["repro_not"].format(why=repro["why"])
    else:
        reproduction = t["repro_none"].format(why=repro["why"])
        if repro.get("steps"):
            reproduction += t["repro_steps"].format(steps=repro["steps"])
    evidence = "\n".join(f"  - `{e['file']}:{e['lines']}`: {e['fact']}" for e in f["evidence"])
    validators = ", ".join(f["validators"])
    return (
        f"### [{f['severity']}] {f['title']}\n\n"
        f"**{t['location']}:** `{f['file']}:{f['lines']}`\n\n"
        f"**{t['category']}:** {f['category']}\n\n"
        f"**{t['attacker']}:** {f['attacker']} {f['preconditions']}\n\n"
        f"**{t['vuln']}:** {f['root_cause']}\n\n"
        f"**{t['exploit']}:** {f['exploit_scenario']}\n\n"
        f"**{t['impact']}:** {f['impact']}\n\n"
        f"**{t['evidence']}:**\n{evidence}\n\n"
        f"**{t['validation']}:** {t['validation_fmt'].format(n=len(f['validators']), v=validators)}\n\n"
        f"**{t['repro']}:** {reproduction}\n\n"
        f"**{t['fix']}:** {f['suggested_fix']}\n"
    )


def cmd_report(args):
    work = Path(args.work).resolve()
    state = load_state(work)
    repo = Path(state["repo"])
    lang = report_lang(state)
    t = STRINGS[lang]
    plan, results = collect_verdicts(work, repo)
    rows = read_ledger(work)
    owners = agent_ids(state, "owner")
    errors = apply_coverage(work, rows, owners)
    if errors:
        raise GateError(errors)
    write_ledger(work, rows)
    required, counts, modules, gaps = coverage_summary(rows)
    assigned_validators = sorted({v for vs in plan["assignment"].values() for v in vs})
    owners_done = [a for a in owners if (work / f"review-{a}.json").exists()]
    sweepers_done = [a for a in agent_ids(state, "sweeper") if (work / f"review-{a}.json").exists()]

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
        limits.append(t["lim_gaps"].format(g=len(gaps), r=len(required), p=counts["partial"], s=counts["skipped"], n=counts["pending"]))
    for aid, why in state.get("incomplete", {}).items():
        limits.append(t["lim_incomplete"].format(a=aid, why=why))
    if changed:
        limits.append(t["lim_changed"])
    if state.get("scope"):
        limits.append(t["lim_scope"].format(s=", ".join(state["scope"])))
    limits.append(t["lim_unverified"])
    limit_text = "\n".join(f"  - {x}" for x in limits)

    notes = []
    sensitive = state.get("sensitive_files", [])
    if sensitive:
        notes.append(t["note_sensitive"].format(n=len(sensitive), files=", ".join(f"`{p}`" for p in sensitive[:10]) + (" …" if len(sensitive) > 10 else "")))
    if state.get("secret_leads"):
        notes.append(t["note_leads"].format(n=state["secret_leads"]))
    if not notes:
        notes.append(t["note_none"])

    out = [
        f"# {t['title']}\n",
        f"## {t['summary']}\n",
        f"- **{t['scope']}:** {{{{SCOPE}}}}",
        f"- **{t['arch']}:** {{{{ARCHITECTURE}}}}",
        f"- **{t['files']}:** " + t["files_fmt"].format(rf=reviewed_files, rq=len(required), rm=reviewed_modules, tm=len(modules), full=counts["full"], part=counts["partial"]),
        f"- **{t['agents']}:** " + t["agents_fmt"].format(n=len(owners_done) + len(sweepers_done), o=len(owners_done), s=len(sweepers_done)),
        f"- **{t['validators']}:** {len(assigned_validators)}" + (t["validators_none"] if not assigned_validators else ""),
        f"- **{t['confirmed']} P0:** {sev['P0']}",
        f"- **{t['confirmed']} P1:** {sev['P1']}",
        f"- **{t['confirmed']} P2:** {sev['P2']}",
        f"- **{t['limits']}:**\n{limit_text}\n",
        f"## {t['findings']}\n",
    ]
    if confirmed:
        out.extend(render_finding(f, t) for f in confirmed)
    else:
        out.append(t["no_findings"] + "\n")

    out.append(f"## {t['rejected']}\n")
    out.append(t["rejected_fmt"].format(total=len(plan["assignment"]), merged=len(plan["merged"]), c=len(confirmed), r=len(rejected), p=len(pending)))
    if rejected:
        out.append(t["rejected_by"])
        for cat, n in Counter(r["rejection_category"] for r in rejected).most_common():
            out.append(f"- {REJECTION_CATEGORIES[cat][lang]}: {n}")
        out.append("")
    if pending:
        out.append(t["inconclusive"])
        for r in pending:
            out.append(f"- {r.get('title', r['id'])}: {r['missing_evidence']}")
        out.append("")

    out.append(f"## {t['coverage']}\n")
    out.append(f"| {t['module']} | {t['full']} | {t['partial']} | {t['skipped']} | {t['pending']} |\n|---|---:|---:|---:|---:|")
    items = sorted(modules.items(), key=lambda kv: (-(sum(kv[1].values()) - kv[1]["full"]), kv[0]))
    for name, c in items[:30]:
        out.append(f"| `{name}` | {c['full']} | {c['partial']} | {c['skipped']} | {c['pending']} |")
    if len(items) > 30:
        out.append("\n" + t["more_modules"].format(n=len(items) - 30))
    reasons = Counter(r["note"].split(":")[0] for r in rows if r["category"] == "excluded")
    out.append(f"\n**{t['excluded']}:** " + (", ".join(f"{k} ({v})" for k, v in reasons.most_common()) or t["nothing"]))
    if state.get("reclass"):
        out.append(f"\n**{t['reclass']}:** " + "; ".join(f"`{x['glob']}` → {x['category']} ({x['reason']})" for x in state["reclass"]))
    out.append("\n{{COVERAGE_NOTES}}\n")
    out.append(f"## {t['notes']}\n")
    out.extend(f"- {n}" for n in notes)
    out.append(f"\n## {t['assessment']}\n\n{{{{FINAL_ASSESSMENT}}}}\n")

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
    t = STRINGS[report_lang(state)]
    text = Path(args.report).read_text()
    errors = []
    left = sorted(set(re.findall(r"\{\{[A-Z_]+\}\}", text)))
    if left:
        errors.append(f"unfilled placeholders: {left}")
    for sev in SEVERITIES:
        count = len(re.findall(rf"^#+\s*\[{sev}\]", text, re.M))
        if count != expected[sev]:
            errors.append(f"{sev}: report has {count} findings, validation confirmed {expected[sev]}")
    for name in find_secrets(text):
        errors.append(f"report matches secret pattern {name}; mask it")
    if not sum(expected.values()) and t["no_findings"] not in text:
        errors.append("a report with no findings must state the required no-findings sentence")
    if errors:
        raise GateError(errors)
    print("report passed the final gate")


def cmd_status(args):
    work = Path(args.work).resolve()
    state = load_state(work)
    agents = agent_ids(state)
    print(f"repo: {state['repo']}\nwork: {work}\nlanguage: {state.get('language', 'English')}")
    if not state.get("plan"):
        print("next: recon (recon.md), then plan")
        return
    if not agents:
        print(f"plan: {state['plan']}\nnext: suggest/assign")
        return
    done = [a for a in agents if (work / f"review-{a}.json").exists() and json.loads((work / f"review-{a}.json").read_text()).get("complete") is True]
    print(f"agents: {len(agents)} assigned, {len(done)} finished")
    if len(done) < len(agents):
        print(f"next: launch or resume unfinished agents: {[a for a in agents if a not in done]}")
    elif not (work / "candidates.json").exists():
        print("next: audit, fill gaps, then candidates")
    elif not (work / "validation-assignment.json").exists():
        print("next: merge duplicates and run partition")
    else:
        plan = json.loads((work / "validation-assignment.json").read_text())
        needed = sorted({v for vs in plan["assignment"].values() for v in vs})
        have = [v for v in needed if (work / f"verdict-{v}.json").exists()]
        if len(have) < len(needed):
            print(f"next: launch or resume validators {[v for v in needed if v not in have]}")
        elif state.get("expected") is None:
            print("next: report")
        else:
            print("next: fill placeholders in report-skeleton.md -> report.md, check-report, deliver")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("init")
    p.add_argument("repo")
    p.add_argument("--work", required=True)
    p.add_argument("--scope", action="append", default=[])
    p.add_argument("--language", default="English")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)
    p = sub.add_parser("reclass")
    p.add_argument("work")
    p.add_argument("--glob", required=True)
    p.add_argument("--category", required=True)
    p.add_argument("--reason", required=True)
    p.set_defaults(func=cmd_reclass)
    p = sub.add_parser("plan")
    p.add_argument("work")
    p.add_argument("--agents", type=int, default=0)
    p.set_defaults(func=cmd_plan)
    p = sub.add_parser("suggest")
    p.add_argument("work")
    p.set_defaults(func=cmd_suggest)
    p = sub.add_parser("assign")
    p.add_argument("work")
    p.add_argument("--map", required=True)
    p.set_defaults(func=cmd_assign)
    p = sub.add_parser("brief")
    p.add_argument("work")
    p.add_argument("id")
    p.set_defaults(func=cmd_brief)
    p = sub.add_parser("audit")
    p.add_argument("work")
    p.set_defaults(func=cmd_audit)
    p = sub.add_parser("candidates")
    p.add_argument("work")
    p.add_argument("--allow-incomplete", action="append", default=[], metavar="ID=reason")
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
    p = sub.add_parser("status")
    p.add_argument("work")
    p.set_defaults(func=cmd_status)
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
