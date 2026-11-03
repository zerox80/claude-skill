# Phase 5: Final report template

Write `report.md` in German. Keep the headings below and the field labels (`Location:`, `Category:`, and so on), including their English spelling and the verdict tokens, exactly as shown, because `gate report` checks them. All other prose is German. Be concise and technically rigorous.

Include:
- Only candidates marked `CONFIRMED` in `decisions.json`, using their exact title and final severity, sorted P0, then P1, then P2.
- Votes exactly as recorded, without rewording. A rejecting validator stays visible.

Do not include:
- Findings or details of rejected, excluded or unverified candidates. Report them only as counts in `Validierungsstatus`. Details stay in `decisions.json` in the run directory.
- Actual secret values, or anything from a run or agent that did not happen.

## Template

```markdown
# Sicherheitsaudit: <Repository-Name>

Stand: <Commit oder "kein git"> · Datum: <Datum> · Scope: <Zielverzeichnis>

## Zusammenfassung

- **Gesamtbewertung:** <2–3 Sätze zur Sicherheitslage im geprüften Umfang; keine Garantie>
- **Repository-Abdeckung:** <geprüfte Einheiten von Gesamtzahl; wichtigste Lücken>
- **Bestätigte P0-Funde:** <n>
- **Bestätigte P1-Funde:** <n>
- **Bestätigte P2-Funde:** <n>
- **Validierungsstatus:** <3 Reviewer und 3 Validatoren abgeschlossen; x Kandidaten geprüft, y bestätigt, z ausgeschlossen (davon u ungeklärt); Details: `decisions.json` im Run-Verzeichnis>

## Bestätigte Funde

### [P1] <Aussagekräftiger Titel der Schwachstelle>

**Location:** `path/to/file.ts:123-145`

**Category:** <Kategorie>

**Description:** <Was ist verwundbar und warum>

**Attack scenario:** <Realistische Schritte und nötige Rechte>

**Evidence:** <Exakter Codepfad mit Fundstellen; tatsächlich ausgeführte Tests mit Ergebnis oder "statisch geprüft, nicht ausgeführt: <Grund>">

**Impact:** <Konkrete Sicherheitsfolgen>

**Root cause:** <Zugrundeliegender Implementierungsfehler>

**Recommended fix:** <Konkrete, minimale Behebung>

**Validation results:**

- Validator 1: CONFIRMED
- Validator 2: CONFIRMED
- Validator 3: UNCERTAIN

**Confidence:** High

## Abdeckung nach Anwendung, Paket und Subsystem

| Einheit | Art | Pfade | Reviewer 1 | Reviewer 2 | Reviewer 3 |
|---|---|---|---|---|---|
| U01 API-Dienst | application | `apps/api/` | INSPECTED | INSPECTED | PARTIAL |

Ausschlüsse: <Pfad, Grund>

## Nicht vollständig geprüfte Bereiche

<Jede Einheit mit PARTIAL oder NOT_INSPECTED sowie jeder Eintrag aus `could_not_inspect`, mit Pfad und Grund. Sonst: "Keine; alle zugewiesenen Einheiten wurden als INSPECTED gemeldet.">

## Validierungsgrenzen und nicht ausgeführte Prüfungen

<Was nur statisch geprüft wurde, welche Laufzeittests nicht möglich waren und warum, ersetzte Agenten, Hinweise auf Texte im Repository, die das Audit zu beeinflussen versuchten.>

## Gesamtpriorität der Behebung

<Geordnete Liste: was zuerst, was gemeinsam behoben werden sollte, und warum.>
```

## When nothing is confirmed

Put this sentence verbatim under `## Bestätigte Funde`, then a German rendering:

```markdown
No confirmed P0–P2 security vulnerabilities were identified within the reviewed scope.

Innerhalb des geprüften Umfangs wurden keine bestätigten P0–P2-Sicherheitslücken festgestellt. Das ist keine Garantie, dass das Repository sicher ist.
```

All other sections remain required.
