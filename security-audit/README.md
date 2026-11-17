# security-audit — Claude Code Plugin

Security-Review eines ganzen Repos mit Subagents. Gemeldet werden nur **Critical / High / Medium (P0 / P1 / P2)**.

## Ablauf

| Phase | Agents | Was passiert |
|---|---|---|
| 1. Repo anschauen | 1× `repo-mapper` | Stack, Entry Points, Auth, Sinks, Trust Boundaries, Hotspots → Repo-Map |
| 2. Security-Review | 3–5× `security-reviewer` (parallel) | Jeder Reviewer bekommt die Repo-Map und einen oder mehrere von 5 Schwerpunkten: A Login/Rechte · B Injection/Code-Ausführung · C Secrets/Krypto/Datenlecks · D Browser/Web · E Infra/CI/Abhängigkeiten/Logik |
| — Merge | Lead | Duplikate zusammenführen, nur P0–P2, IDs `F-01…` |
| 3. Validierung | 3× `finding-validator` (parallel) | Jeder prüft **alle** Findings selbst im Code: V1 Erreichbarkeit/PoC · V2 False-Positive-Jäger · V3 Impact/Severity (Devil's Advocate) |
| 4. Report | Lead | ≥ 2/3 CONFIRMED → verifiziert · ≥ 2/3 REJECTED → verworfen · Rest → manuell prüfen. Severity = Median. |

Anzahl Reviewer: automatisch (3 klein, 4 mittel/Web-App, 5 groß/Monorepo/Infra) oder per `--reviewers N`:

| Schwerpunkt | 3 Agents | 4 Agents | 5 Agents |
|---|---|---|---|
| A. Login und Rechte | R1 | R1 | R1 |
| B. Injection und Code-Ausführung | R2 | R2 | R2 |
| C. Secrets, Kryptografie, Datenlecks | R3 | R3 | R3 |
| D. Browser-Seite / Web | R3 | R4 | R4 |
| E. Infrastruktur, CI, Abhängigkeiten, Logik | R3 | R3 | R5 |

Alle Agents sind read-only (Read, Grep, Glob, Bash nur lesend). Quellcode wird nicht verändert.

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
/security-audit:audit src/ --reviewers 5
```

Ergebnis landet in `.security-audit/<datum>/` (Repo-Map, Reviews, Kandidaten, Validierungen, `REPORT.md`).
`.security-audit/` in die `.gitignore` aufnehmen — der Report enthält Schwachstellen-Details.

Hinweis: Ein Lauf startet 7–9 Subagents (1 Mapper, 3–5 Reviewer, 3 Validierer) und verbraucht entsprechend viele Tokens.

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
