# deep-security-review

Claude-Code-Plugin für ein repo-weites Security-Review. Es meldet nur **bestätigte** Schwachstellen der Stufen **P0 bis P2** (kritisch, hoch, mittel). Das Plugin ist eigenständig: Es nutzt keine anderen Security-Plugins und kein Workflow-Tool.

## Ablauf

1. **Ganzes Repo erfassen.** `dsr.py init` inventarisiert alle Dateien, schließt Vendor-, generierte und Secret-Dateien aus und sucht per Text-Scan nach Secret-Mustern (nur Fundstellen, nie Werte). Der Orchestrator liest Doku und Einstiegspunkte und schreibt `recon.md` mit Angreifermodell, Trust Boundaries und vorhandenen Schutzmaßnahmen.
2. **Security-Review mit 5–10 Subagents.** Jede erforderliche Datei hat genau einen Besitzer.
   - **Komponenten-Owner (R01…)** lesen ihre Dateien vollständig und prüfen alle Schwachstellenklassen.
   - **Sweeper (S1–S3)** besitzen keine Dateien. Sie suchen je eine Gruppe von Schwachstellenklassen repo-weit: Zugriffskontrolle und Logik-Missbrauch, Injection/SSRF/Dateien/CI, Browser-Seite und Kryptografie.
3. **Validierung mit genau 3 neuen Subagents.** Die Claims sind anonymisiert (ohne Reviewer, Datenfluss und Begründung). Die Validatoren haben unterschiedliche Schwerpunkte: V1 Ausnutzbarkeit, V2 Schutzmaßnahmen, V3 Auswirkung und Schweregrad. Jeder P0-Claim geht an alle 3 Validatoren, jeder P1-Claim an 2, jeder P2-Claim an 1. Bestätigt ist ein Claim nur, wenn **alle** zugewiesenen Validatoren bestätigen.

Das Skript `dsr.py` erzwingt die Reihenfolge: Es prüft Abdeckung, zitierte Dateien und Zeilen, Pflichtfelder und Verdikte. Der Report wird erst erzeugt, wenn alle Verdikte vollständig sind.

## Aufruf

```
/deep-security-review:deep-security-review
/deep-security-review:deep-security-review --scope lib --scope src/stores
/deep-security-review:deep-security-review --agents 5 --parallel 3 --reviewer-model sonnet
```

Der Skill ist absichtlich nur manuell aufrufbar (`disable-model-invocation`), damit Claude ihn nie von selbst startet.

| Argument | Wirkung |
|---|---|
| `--scope <pfad>` | Nur dieses Unterverzeichnis prüfen (mehrfach möglich). |
| `--agents N` | Anzahl Reviewer, 5–10. Standard: nach Codemenge berechnet. Validatoren sind immer 3. |
| `--parallel N` | Wie viele Agents gleichzeitig laufen (Standard 5). |
| `--reviewer-model <m>` | Modell nur für Reviewer, z. B. `sonnet`. Standard: erbt das Sitzungsmodell. |
| `--yes` | Bestätigungsfrage vor dem Start überspringen. |

## Kostenbremsen

Das Review ist teuer. Der Aufwand wächst vor allem mit den Codezeilen im Umfang, weil jede erforderliche Datei einmal vollständig gelesen wird.

- Vor dem Start zeigt der Skill den Plan und fragt nach (ohne `--yes`).
- Agents laufen in Wellen, nach Risiko sortiert, sodass du zwischen den Wellen abbrechen kannst.
- Die wirksamsten Hebel: engeres `--scope`, korrekte Ausschlüsse (Vendor, generierte Dateien), weniger Agents, günstigeres `--reviewer-model`.

## Aufbau

```
.claude-plugin/plugin.json
agents/security-reviewer.md         Worker: Komponenten-Owner oder Sweeper
agents/security-validator.md        Worker: Validator
skills/deep-security-review/
  SKILL.md                          Orchestrator-Anleitung (Schritte 1–8)
  scripts/dsr.py                    Buchführung, Phasen-Gates, Report
  references/
    reviewer-brief.md               Auftrag und JSON-Schema der Reviewer
    validator-brief.md              Auftrag und JSON-Schema der Validatoren
    severity-and-scope.md           P0–P2-Rubrik, Ausschlüsse, Pflichtangaben je Finding
    sweeper-lenses.md               Prüfblickwinkel der Sweeper
```

Die Agents holen sich ihren Auftrag selbst mit `dsr.py brief`. Das hält den Kontext des Orchestrators klein.

## Installation

Das Plugin liegt in `~/.claude/skills/deep-security-review/` und lädt damit global als `deep-security-review@skills-dir`, in jeder Sitzung und jedem Projekt. In einer laufenden Sitzung `/reload-plugins` ausführen. Abschalten: `claude plugin disable deep-security-review@skills-dir`. Entfernen: den Ordner löschen.

## Grenzen

- Ein sauberes Ergebnis gilt nur für den geprüften Umfang und ist kein Sicherheitsbeweis. Es ersetzt weder einen Penetrationstest noch eine Dependency-Prüfung.
- Der Prüfstatus pro Datei wird von den Reviewern gemeldet und nicht unabhängig verifiziert.
- Bestätigte Schwachstellen gehören in den privaten Meldeweg des Projekts (`SECURITY.md`), nicht in öffentliche Issues. Das Plugin legt nirgends selbst etwas an.
- Stand: statisch geprüft (Syntax, Manifest). Es wurde bewusst noch kein Review-Lauf gemacht.
