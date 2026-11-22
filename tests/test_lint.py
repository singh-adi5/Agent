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
# Technique and Sentinel tactics per detection, checked against the ATT&CK dataset.
EXPECTED = {
    "adminsdholder": ("T1098", ["Persistence", "PrivilegeEscalation"]),
    "asrep-roasting": ("T1558.004", ["CredentialAccess"]),
    "dcshadow": ("T1207", ["DefenseEvasion"]),
    "dcsync": ("T1003.006", ["CredentialAccess"]),
    "golden-ticket": ("T1558.001", ["CredentialAccess"]),
    "kerberoasting": ("T1558.003", ["CredentialAccess"]),
    "password-spraying": ("T1110.003", ["CredentialAccess"]),
}


class RepositoryContent(unittest.TestCase):
    def test_every_file_passes(self):
        failures = {k: v for k, v in lint.lint_repository().items() if v}
        self.assertEqual(failures, {})

    def test_each_detection_maps_to_its_technique(self):
        self.assertEqual({d.name for d in catalog.detection_dirs()}, set(EXPECTED))
        for name, (technique, tactics) in EXPECTED.items():
            for filename in (catalog.ANALYTIC, catalog.HUNTING):
                document = catalog.load_yaml(ROOT / "detections" / name / filename)
                with self.subTest(file=f"{name}/{filename}"):
                    self.assertEqual(document["relevantTechniques"], [technique])
                    self.assertEqual(document["tactics"], tactics)

    def test_no_allow_list_is_hard_coded_in_a_query(self):
        for folder in catalog.detection_dirs():
            query = catalog.load_yaml(folder / catalog.ANALYTIC)["query"]
            with self.subTest(detection=folder.name):
                self.assertNotIn("dynamic([", query)


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

    def test_unknown_watchlist_alias_fails(self):
        rule = yaml.safe_load(self.analytic.read_text())
        rule["query"] = rule["query"].replace("ADDetectionExclusions", "NoSuchList")
        self.analytic.write_text(yaml.safe_dump(rule, sort_keys=False))
        shutil.copytree(ROOT / "watchlists", self.root / "watchlists")
        errors = lint.lint_repository(self.root)["detections/kerberoasting/analytic.yaml"]
        self.assertIn("query reads unknown watchlist 'NoSuchList'", errors)

    def test_missing_file_fails(self):
        (self.folder / catalog.README).unlink()
        results = lint.lint_repository(self.root)
        self.assertIn("missing README.md", results["detections/kerberoasting"])
        with redirect_stdout(io.StringIO()) as output:
            self.assertEqual(lint.main(["lint", str(self.root)]), 1)
        self.assertIn("FAIL detections/kerberoasting", output.getvalue())


class BrokenTests(unittest.TestCase):
    columns = {name for name, _ in catalog.load_schema()}
    headers = {"ADDetectionExclusions": ["Detection", "Value", "Reason", "Owner", "ExpiresOn"]}

    def lint_cases(self, cases, produced=None):
        path = Path(tempfile.mkdtemp()) / "tests.json"
        self.addCleanup(shutil.rmtree, path.parent)
        path.write_text(json.dumps({"cases": cases}))
        return lint.lint_tests(path, self.columns, self.headers, produced)

    def test_assert_on_a_column_the_rule_does_not_output_fails(self):
        cases = [
            {"name": "a", "expect": "fire", "assert": {"Nope": 1}, "events": [{"EventID": 1}]},
            {"name": "b", "expect": "silent", "events": [{"EventID": 1}]},
        ]
        self.assertEqual(
            self.lint_cases(cases, produced={"Requester"}),
            ["a: assert uses non-output column(s) Nope"],
        )

    def test_assert_on_a_silent_case_fails(self):
        cases = [
            {"name": "a", "expect": "fire", "events": [{"EventID": 1}]},
            {"name": "b", "expect": "silent", "assert": {"X": 1}, "events": [{"EventID": 1}]},
        ]
        self.assertEqual(
            self.lint_cases(cases), ["b: assert must be a non-empty object on a 'fire' case"]
        )

    def test_watchlist_rows_must_match_a_known_watchlist(self):
        cases = [
            {
                "name": "a",
                "expect": "fire",
                "watchlist": [{"alias": "Nope"}, {"alias": "ADDetectionExclusions", "Colour": "x"}],
                "events": [{"EventID": 1}],
            },
            {"name": "b", "expect": "silent", "events": [{"EventID": 1}]},
        ]
        self.assertEqual(
            self.lint_cases(cases),
            ["a: unknown watchlist 'Nope'", "a: ADDetectionExclusions has no column(s) Colour"],
        )

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


class Watchlists(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        shutil.copytree(ROOT / "watchlists", self.root / "watchlists")
        self.exclusions = self.root / "watchlists" / "ADDetectionExclusions.csv"

    def lint_with_row(self, row):
        self.exclusions.write_text("Detection,Value,Reason,Owner,ExpiresOn\n" + row + "\n")
        names = {d.name for d in catalog.detection_dirs()}
        return lint.lint_watchlists(self.root, names)["watchlists/ADDetectionExclusions.csv"]

    def test_repository_watchlists_pass(self):
        names = {d.name for d in catalog.detection_dirs()}
        self.assertEqual({k: v for k, v in lint.lint_watchlists(ROOT, names).items() if v}, {})

    def test_valid_exclusion_passes(self):
        self.assertEqual(self.lint_with_row("dcsync,msol_abc,sync,identity,2027-01-31"), [])

    def test_unknown_detection_fails(self):
        self.assertEqual(
            self.lint_with_row("dcsink,msol_abc,sync,identity,"),
            ["line 2: unknown detection 'dcsink'"],
        )

    def test_bad_expiry_date_fails(self):
        self.assertEqual(
            self.lint_with_row("dcsync,msol_abc,sync,identity,31/01/2027"),
            ["line 2: ExpiresOn must be YYYY-MM-DD"],
        )

    def test_iso_week_date_fails(self):
        # Python accepts 2099-W01-1 as ISO 8601; KQL's todatetime() does not.
        self.assertEqual(
            self.lint_with_row("dcsync,msol_abc,sync,identity,2099-W01-1"),
            ["line 2: ExpiresOn must be YYYY-MM-DD"],
        )

    def test_surrounding_space_fails(self):
        self.assertEqual(
            self.lint_with_row("dcsync, msol_abc ,sync,identity,"),
            ["line 2: leading or trailing space in Value"],
        )

    def test_domain_controller_dn_must_use_semicolons(self):
        dcs = self.root / "watchlists" / "ADDomainControllers.csv"
        dcs.write_text(
            "SamAccountName,Hostname,DistinguishedName\n"
            'dc01$,dc01.contoso.local,"CN=DC01,OU=Domain Controllers,DC=contoso,DC=local"\n'
        )
        names = {d.name for d in catalog.detection_dirs()}
        errors = lint.lint_watchlists(self.root, names)["watchlists/ADDomainControllers.csv"]
        self.assertTrue(any("DistinguishedName must start with CN=" in e for e in errors))

    def test_empty_search_key_fails(self):
        self.assertEqual(self.lint_with_row("dcsync,,sync,identity,"), ["line 2: empty Value"])
