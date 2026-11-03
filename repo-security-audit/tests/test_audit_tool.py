#!/usr/bin/env python3
"""Tests for scripts/audit_tool.py. Run: python3 -I tests/test_audit_tool.py"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parent.parent / "scripts" / "audit_tool.py"
LOC = [{"path": "apps/api/app.py", "start": 2, "end": 3}]
NONE = "No confirmed P0–P2 security vulnerabilities were identified within the reviewed scope."


def candidate(local_id):
    return {
        "local_id": local_id, "title": "SQLi", "severity": "P1", "category": "SQLi", "locations": LOC,
        "prerequisites": "login", "attack_path": ["a"], "impact": "b", "root_cause": "c",
    }


def verdict(cid, value, sev="P1"):
    return {
        "candidate_id": cid, "verdict": value, "evidence": [dict(LOC[0], note="n")], "exploitability": "e",
        "recommended_severity": sev, "explanation": "x", "execution": {"performed": False, "level": "static"},
    }


REPORT = """# Sicherheitsaudit: x

## Zusammenfassung

- **Gesamtbewertung:** a
- **Repository-Abdeckung:** b
- **Bestätigte P0-Funde:** 0
- **Bestätigte P1-Funde:** {p1}
- **Bestätigte P2-Funde:** {p2}
- **Validierungsstatus:** c

## Bestätigte Funde

{findings}

## Abdeckung nach Anwendung, Paket und Subsystem

t

## Nicht vollständig geprüfte Bereiche

{gaps}

## Validierungsgrenzen und nicht ausgeführte Prüfungen

l

## Gesamtpriorität der Behebung

r
"""

FINDING = """### [{sev}] SQL injection in search

**Location:** `{loc}`

**Category:** SQLi

**Description:** d

**Attack scenario:** a

**Evidence:** e

**Impact:** i

**Root cause:** r

**Recommended fix:** f

**Validation results:**

- Validator 1: CONFIRMED
- Validator 2: CONFIRMED
- Validator 3: REJECTED

**Confidence:** Medium
"""


class ToolTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.env = dict(os.environ, XDG_STATE_HOME=str(self.tmp / "state"))
        self.target = self.tmp / "repo"
        (self.target / "apps/api").mkdir(parents=True)
        (self.target / "apps/api/app.py").write_text("a\nb\nc\n")
        (self.target / "apps/api/requirements.txt").write_text("flask==3.0\n")
        (self.target / "apps/api/pyproject.toml").write_text("[project]\n")
        (self.target / "vendor").mkdir()
        (self.target / "vendor/lib.js").write_text("x\n")
        out = self.tool("init", "--target", str(self.target)).stdout
        self.run_dir = Path(out.splitlines()[0].split("=", 1)[1])
        self.tool("inventory", "--run", str(self.run_dir))

    def tool(self, *args, check=True):
        res = subprocess.run([sys.executable, "-I", str(TOOL), *args], capture_output=True, text=True, env=self.env)
        if check:
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        return res

    def gate(self, stage):
        return self.tool("gate", stage, "--run", str(self.run_dir), check=False)

    def put(self, rel, data):
        path = self.run_dir / rel
        path.write_text(data if isinstance(data, str) else json.dumps(data))

    def coverage(self):
        self.put("recon.md", "x" * 300)
        self.put("coverage.json", {
            "units": [{"id": "U01", "name": "API", "kind": "application", "paths": ["apps/api/"], "reviewers": [1, 2, 3]}],
            "exclusions": [{"path": "vendor/", "reason": "third-party"}],
        })

    def reviews(self, cands=True):
        for n in (1, 2, 3):
            self.put(f"review/reviewer-{n}.json", {
                "reviewer": n, "agent_id": f"r{n}", "status": "COMPLETE",
                "units": [{"id": "U01", "status": "INSPECTED"}],
                "candidates": [candidate(f"R{n}-01")] if cands and n == 1 else [],
            })

    def merged(self):
        self.put("candidates.json", {"candidates": [{
            "id": "C-001", "title": "SQLi", "proposed_severity": "P1", "locations": LOC, "sources": ["R1-01"],
        }]})

    def validations(self, values=("CONFIRMED", "CONFIRMED", "REJECTED"), sevs=("P1", "P2", "P2")):
        for n, value, sev in zip((1, 2, 3), values, sevs):
            self.put(f"validation/validator-{n}.json", {
                "validator": n, "agent_id": f"v{n}", "status": "COMPLETE", "verdicts": [verdict("C-001", value, sev)],
            })

    def decision(self, **extra):
        base = {
            "candidate_id": "C-001", "decision": "CONFIRMED", "title": "SQL injection in search",
            "final_severity": "P2", "confidence": "Medium", "disagreement_resolution": "re-read",
            "criteria": {k: "y" for k in ("concrete_source_evidence", "exploit_path_demonstrated", "not_neutralized", "severity_justified")},
        }
        base.update(extra)
        self.put("decisions.json", {"decisions": [base]})

    def through_validation(self):
        self.coverage()
        self.reviews()
        self.merged()
        self.validations()
        self.assertEqual(self.gate("review").returncode, 0)
        self.assertEqual(self.gate("validation").returncode, 0, self.gate("validation").stdout)

    def test_recon_requires_every_file_accounted(self):
        self.coverage()
        self.assertEqual(self.gate("recon").returncode, 0, self.gate("recon").stdout)
        self.put("coverage.json", {"units": [{"id": "U01", "paths": ["apps/api/"], "reviewers": [1, 2, 3]}]})
        res = self.gate("recon")
        self.assertEqual(res.returncode, 1)
        self.assertIn("neither a unit nor an exclusion", res.stdout)

    def test_recon_requires_unit_per_package(self):
        self.put("recon.md", "x" * 300)
        self.put("coverage.json", {
            "units": [{"id": "U01", "paths": ["apps/"], "reviewers": [1, 2, 3]}],
            "exclusions": [{"path": "vendor/", "reason": "third-party"}],
        })
        res = self.gate("recon")
        self.assertEqual(res.returncode, 1)
        self.assertIn("no unit of its own", res.stdout)

    def test_review_fails_with_only_two_reviewers(self):
        self.coverage()
        self.reviews()
        (self.run_dir / "review/reviewer-3.json").unlink()
        self.assertEqual(self.gate("review").returncode, 1)

    def test_review_rejects_invented_line_and_p3(self):
        self.coverage()
        self.reviews()
        bad = candidate("R1-01")
        bad["locations"] = [{"path": "apps/api/app.py", "start": 900, "end": 901}]
        bad["severity"] = "P3"
        self.put("review/reviewer-1.json", {
            "reviewer": 1, "agent_id": "r1", "status": "COMPLETE",
            "units": [{"id": "U01", "status": "INSPECTED"}], "candidates": [bad],
        })
        res = self.gate("review")
        self.assertIn("beyond end", res.stdout)
        self.assertIn("severity must be", res.stdout)

    def test_candidates_cannot_be_silently_dropped(self):
        self.coverage()
        self.reviews()
        self.put("candidates.json", {"candidates": []})
        self.assertIn("dropped", self.gate("candidates").stdout)

    def test_validator_observation_can_become_candidate(self):
        self.coverage()
        self.reviews()
        self.put("candidates.json", {"candidates": [
            {"id": "C-001", "title": "SQLi", "proposed_severity": "P1", "locations": LOC, "sources": ["R1-01"]},
            {"id": "C-002", "title": "New", "proposed_severity": "P2", "locations": LOC, "sources": ["V2-obs-1"]},
        ]})
        self.assertEqual(self.gate("candidates").returncode, 0, self.gate("candidates").stdout)

    def test_validation_requires_all_verdicts_and_distinct_agents(self):
        self.coverage()
        self.reviews()
        self.merged()
        self.validations()
        data = json.loads((self.run_dir / "validation/validator-2.json").read_text())
        data["verdicts"] = []
        data["agent_id"] = "r1"
        self.put("validation/validator-2.json", data)
        res = self.gate("validation")
        self.assertIn("no verdict for C-001", res.stdout)
        self.assertIn("distinct", res.stdout)

    def test_two_confirmations_take_lower_severity(self):
        self.through_validation()
        adj = json.loads((self.run_dir / "adjudication.json").read_text())["C-001"]
        self.assertEqual(adj["computed_severity"], "P2")
        self.assertTrue(adj["eligible"])
        self.assertTrue(adj["disagreement"])

    def test_cannot_confirm_without_two_votes(self):
        self.coverage()
        self.reviews()
        self.merged()
        self.validations(("CONFIRMED", "UNCERTAIN", "REJECTED"))
        self.assertEqual(self.gate("validation").returncode, 0)
        self.decision()
        self.assertIn("without eligibility", self.gate("decisions").stdout)

    def test_below_p2_is_not_eligible(self):
        self.coverage()
        self.reviews()
        self.merged()
        self.validations(("CONFIRMED", "CONFIRMED", "REJECTED"), ("P2", "BELOW_P2", "P2"))
        self.gate("validation")
        adj = json.loads((self.run_dir / "adjudication.json").read_text())["C-001"]
        self.assertFalse(adj["eligible"])

    def test_cannot_raise_severity(self):
        self.through_validation()
        self.decision(final_severity="P1")
        self.assertIn("raised above", self.gate("decisions").stdout)

    def good_report(self, **kw):
        finding = FINDING.format(sev="P2", loc=kw.get("loc", "apps/api/app.py:2-3"))
        return REPORT.format(p1=0, p2=kw.get("p2", 1), findings=finding, gaps="Keine")

    def test_report_happy_path_and_vote_mismatch(self):
        self.through_validation()
        self.decision()
        self.assertEqual(self.gate("decisions").returncode, 0, self.gate("decisions").stdout)
        self.put("report.md", self.good_report())
        self.assertEqual(self.gate("report").returncode, 0, self.gate("report").stdout)
        self.put("report.md", self.good_report().replace("Validator 3: REJECTED", "Validator 3: CONFIRMED"))
        self.assertIn("Validator 3", self.gate("report").stdout)

    def test_report_rejects_unconfirmed_finding_bad_count_location_and_secret(self):
        self.through_validation()
        self.decision()
        extra = "### [P1] Not validated\n\nx\n\n"
        text = self.good_report(p2=4, loc="apps/api/nope.py:1").replace("### [P2]", extra + "### [P2]", 1)
        text += "\nAKIAIOSFODNN7EXAMPLE\n"
        self.put("report.md", text)
        out = self.gate("report").stdout
        self.assertIn("not confirmed", out)
        self.assertIn("summary says 4", out)
        self.assertIn("does not exist", out)
        self.assertIn("secret", out)

    def test_zero_findings_requires_sentence_and_gap_disclosure(self):
        self.coverage()
        self.reviews(cands=False)
        data = json.loads((self.run_dir / "review/reviewer-2.json").read_text())
        data["units"] = [{"id": "U01", "status": "PARTIAL", "note": "ran out"}]
        self.put("review/reviewer-2.json", data)
        self.put("candidates.json", {"candidates": []})
        for n in (1, 2, 3):
            self.put(f"validation/validator-{n}.json", {"validator": n, "agent_id": f"v{n}", "status": "COMPLETE", "verdicts": []})
        self.assertEqual(self.gate("review").returncode, 0, self.gate("review").stdout)
        self.assertEqual(self.gate("validation").returncode, 0, self.gate("validation").stdout)
        self.put("decisions.json", {"decisions": []})
        self.assertEqual(self.gate("decisions").returncode, 0)
        self.put("report.md", REPORT.format(p1=0, p2=0, findings="nichts", gaps="Keine"))
        out = self.gate("report").stdout
        self.assertIn("required sentence", out)
        self.assertIn("not disclosed", out)
        self.put("report.md", REPORT.format(p1=0, p2=0, findings=NONE, gaps="U01 teilweise"))
        self.assertEqual(self.gate("report").returncode, 0, self.gate("report").stdout)

    def test_validation_still_required_with_zero_candidates(self):
        self.coverage()
        self.reviews(cands=False)
        self.put("candidates.json", {"candidates": []})
        self.assertEqual(self.gate("validation").returncode, 1)

    def test_inventory_does_not_follow_symlink_or_write_to_target(self):
        os.symlink("/etc/passwd", self.target / "link")
        before = sorted(str(p) for p in self.target.rglob("*"))
        self.tool("inventory", "--run", str(self.run_dir))
        rows = [json.loads(line) for line in (self.run_dir / "inventory.jsonl").read_text().splitlines()]
        link = next(r for r in rows if r["path"] == "link")
        self.assertEqual(link["category"], "symlink")
        self.assertIsNone(link["lines"])
        self.assertEqual(before, sorted(str(p) for p in self.target.rglob("*")))

    def test_location_cannot_escape_target(self):
        self.coverage()
        self.reviews()
        bad = candidate("R1-01")
        bad["locations"] = [{"path": "../../../etc/passwd", "start": 1, "end": 1}]
        self.put("review/reviewer-1.json", {
            "reviewer": 1, "agent_id": "r1", "status": "COMPLETE",
            "units": [{"id": "U01", "status": "INSPECTED"}], "candidates": [bad],
        })
        self.assertIn("escapes target", self.gate("review").stdout)


if __name__ == "__main__":
    unittest.main()
