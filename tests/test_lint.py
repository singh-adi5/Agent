import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import yaml

from tools import catalog, lint

ROOT = catalog.REPO_ROOT
EXPECTED_TECHNIQUES = {
    "asrep-roasting": "T1558.004",
    "dcsync": "T1003.006",
    "golden-ticket": "T1558.001",
    "kerberoasting": "T1558.003",
    "password-spraying": "T1110.003",
}


class RepositoryContent(unittest.TestCase):
    def test_every_file_passes(self):
        failures = {k: v for k, v in lint.lint_repository().items() if v}
        self.assertEqual(failures, {})

    def test_each_detection_maps_to_its_technique(self):
        self.assertEqual({d.name for d in catalog.detection_dirs()}, set(EXPECTED_TECHNIQUES))
        for name, technique in EXPECTED_TECHNIQUES.items():
            for filename in (catalog.ANALYTIC, catalog.HUNTING):
                document = catalog.load_yaml(ROOT / "detections" / name / filename)
                with self.subTest(file=f"{name}/{filename}"):
                    self.assertEqual(document["relevantTechniques"], [technique])
                    self.assertEqual(document["tactics"], ["CredentialAccess"])


class BrokenContent(unittest.TestCase):
    """Copy one detection into a scratch repository, break it, and expect a lint failure."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.folder = self.root / "detections" / "kerberoasting"
        shutil.copytree(ROOT / "detections" / "kerberoasting", self.folder)
        self.analytic = self.folder / catalog.ANALYTIC

    def edit_analytic(self, change):
        rule = yaml.safe_load(self.analytic.read_text())
        change(rule)
        self.analytic.write_text(yaml.safe_dump(rule, sort_keys=False))
        return lint.lint_analytic(self.analytic)

    def test_every_required_field_is_enforced(self):
        original = self.analytic.read_text()
        for field in lint.ANALYTIC_FIELDS:
            self.analytic.write_text(original)
            with self.subTest(field=field):
                errors = self.edit_analytic(lambda rule, f=field: rule.pop(f))
                self.assertIn(f"missing field '{field}'", errors)

    def test_malformed_attack_id_fails(self):
        errors = self.edit_analytic(lambda r: r.update(relevantTechniques=["Kerberoasting"]))
        self.assertTrue(any("ATT&CK" in e for e in errors))

    def test_entity_column_must_be_an_output_column(self):
        def change(rule):
            rule["entityMappings"][0]["fieldMappings"][0]["columnName"] = "RawUser"

        self.assertTrue(any("RawUser" in e for e in self.edit_analytic(change)))

    def test_alert_title_placeholder_must_be_an_output_column(self):
        errors = self.edit_analytic(
            lambda r: r.update(alertDetailsOverride={"alertDisplayNameFormat": "{{EncType}}"})
        )
        self.assertTrue(any("EncType" in e for e in errors))

    def test_custom_details_as_a_list_fails_without_crashing(self):
        errors = self.edit_analytic(lambda r: r.update(customDetails=["Requester"]))
        self.assertIn("customDetails must map a name to a column", errors)

    def test_period_shorter_than_frequency_fails(self):
        errors = self.edit_analytic(lambda r: r.update(queryFrequency="1h", queryPeriod="30m"))
        self.assertTrue(any("queryPeriod is shorter" in e for e in errors))

    def test_invalid_yaml_fails_without_crashing(self):
        self.analytic.write_text("id: [unclosed\n")
        self.assertTrue(lint.lint_analytic(self.analytic)[0].startswith("not valid YAML"))

    def test_duplicate_id_across_files_fails(self):
        rule_id = yaml.safe_load(self.analytic.read_text())["id"]
        hunting = self.folder / catalog.HUNTING
        hunt = yaml.safe_load(hunting.read_text())
        hunt["id"] = rule_id
        hunting.write_text(yaml.safe_dump(hunt, sort_keys=False))
        errors = lint.lint_repository(self.root)["detections/kerberoasting/hunting.yaml"]
        self.assertTrue(any("id is also used by" in e for e in errors))

    def test_missing_file_fails(self):
        (self.folder / catalog.README).unlink()
        results = lint.lint_repository(self.root)
        self.assertIn("missing README.md", results["detections/kerberoasting"])
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(lint.main(["lint", str(self.root)]), 1)
        self.assertIn("FAIL detections/kerberoasting", output.getvalue())


class BrokenTests(unittest.TestCase):
    columns = {name for name, _ in catalog.load_schema()}

    def lint_cases(self, cases):
        path = Path(tempfile.mkdtemp()) / "tests.json"
        self.addCleanup(shutil.rmtree, path.parent)
        path.write_text(json.dumps({"cases": cases}))
        return lint.lint_tests(path, self.columns)

    def test_misspelt_column_fails(self):
        cases = [
            {"name": "a", "expect": "fire", "events": [{"EventId": 4769}]},
            {"name": "b", "expect": "silent", "events": [{"EventID": 4769}]},
        ]
        self.assertEqual(self.lint_cases(cases), ["a: unknown column(s) EventId"])

    def test_needs_both_a_fire_and_a_silent_case(self):
        cases = [{"name": "a", "expect": "fire", "events": [{"EventID": 4769}]}]
        self.assertEqual(self.lint_cases(cases), ["needs at least one 'silent' case"])


if __name__ == "__main__":
    unittest.main()
