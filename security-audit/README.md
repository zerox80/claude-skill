# security-audit — Claude Code Plugin

Security-Review eines ganzen Repos mit Subagents. Gemeldet werden nur **Critical / High / Medium (P0 / P1 / P2)**.

## Ablauf

| Phase | Agents | Was passiert |
|---|---|---|
| 1. Repo anschauen | 1x `repo-mapper` | Stack, Entry Points, Auth, Sinks, Trust Boundaries, Hotspots -> Repo-Map |
| 2. Security-Check | 10x `security-reviewer` (max. 5 gleichzeitig) | Jeder Reviewer bekommt die Repo-Map und genau einen Schwerpunkt (siehe unten) |
| - Merge | Lead | Duplikate zusammenfuehren, nur P0-P2, IDs `F-01...` |
| 3. Validierung | 3x `finding-validator` (parallel) | Jeder prueft **alle** Findings selbst im Code: V1 Erreichbarkeit/PoC, V2 False-Positive-Jaeger, V3 Impact/Severity |
| 4. Report | Lead | >= 2/3 CONFIRMED = verifiziert, >= 2/3 REJECTED = verworfen, Rest = manuell pruefen. Severity = Median. |

Es laufen nie mehr als 5 Subagents gleichzeitig: R1-R5 starten zusammen, R6-R10 rutschen nach, sobald ein Platz frei wird. Die Validierer starten erst danach.

| ID | Schwerpunkt |
|---|---|
| R1 | Authentifizierung und Sessions |
| R2 | Autorisierung, IDOR, Mandantentrennung |
| R3 | Injection (SQL, Command, Template) |
| R4 | Dateien, Deserialisierung, SSRF |
| R5 | Secrets und Kryptografie |
| R6 | Datenlecks und API-Oberflaeche |
| R7 | Client-seitig / Web (XSS, Redirects, CSP) |
| R8 | CI/CD, Container, IaC |
| R9 | Abhaengigkeiten und Supply Chain |
| R10 | Logik, Race Conditions, Missbrauch |

Mit `--reviewers N` (3 bis 10) werden benachbarte Schwerpunkte zusammengelegt.

Alle Agents sind read-only (Read, Grep, Glob, Bash nur lesend). Quellcode wird nicht veraendert.

## Installation

In Claude Code:

```
/plugin marketplace add zerox80/claude-skill
/plugin install security-audit@claude-skill
```

Danach eine neue Claude-Code-Sitzung starten.

## Benutzung

Im Ziel-Repo:

```
/security-audit:audit
/security-audit:audit src/ --reviewers 6
```

Ergebnis landet in `.security-audit/<datum>/` (Repo-Map, Reviews, Kandidaten, Validierungen, `REPORT.md`).
`.security-audit/` in die `.gitignore` aufnehmen — der Report enthält Schwachstellen-Details.

Hinweis: Ein Lauf startet 14 Subagents (1 Mapper, 10 Reviewer, 3 Validierer) und verbraucht entsprechend viele Tokens.

## Struktur

```
security-audit/
├── .claude-plugin/plugin.json
├── skills/audit/SKILL.md          # Orchestrierung (Phasen 0–4)
└── agents/
    ├── repo-mapper.md
    ├── security-reviewer.md
    └── finding-validator.md
```
