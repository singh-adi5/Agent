"""Tests for the rule validator and the ARM converter. Run: python -m unittest discover -s tests"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT / "deployment"))

import validate_rules  # noqa: E402
import yaml_to_arm  # noqa: E402

EXPECTED = {
    "kerberoasting": "T1558.003",
    "asrep-roasting": "T1558.004",
    "dcsync": "T1003.006",
    "password-spraying": "T1110.003",
    "golden-ticket": "T1558.001",
}


class RepositoryRules(unittest.TestCase):
    def test_all_four_rules_pass(self):
        for name in EXPECTED:
            with self.subTest(rule=name):
                self.assertEqual(validate_rules.validate_rule(ROOT / "detections" / name / "rule.yaml"), [])

    def test_each_rule_maps_to_its_technique(self):
        for name, technique in EXPECTED.items():
            rule = yaml.safe_load((ROOT / "detections" / name / "rule.yaml").read_text())
            with self.subTest(rule=name):
                self.assertEqual(rule["relevantTechniques"], [technique])
                self.assertEqual(rule["tactics"], ["CredentialAccess"])

    def test_main_exit_code(self):
        self.assertEqual(validate_rules.main(["validate_rules.py", str(ROOT)]), 0)


class HuntingQueries(unittest.TestCase):
    def test_every_detection_has_a_hunting_query_that_passes(self):
        for name, technique in EXPECTED.items():
            path = ROOT / "hunting" / f"{name}.yaml"
            with self.subTest(hunt=name):
                self.assertEqual(validate_rules.validate_hunting_query(path), [])
                self.assertEqual(yaml.safe_load(path.read_text())["relevantTechniques"], [technique])

    def test_drift_from_the_kql_file_fails(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        for suffix in (".yaml", ".kql"):
            shutil.copy(ROOT / "hunting" / f"dcsync{suffix}", tmp / f"dcsync{suffix}")
        hunt = yaml.safe_load((tmp / "dcsync.yaml").read_text())
        hunt["query"] += "\n| take 1"
        (tmp / "dcsync.yaml").write_text(yaml.safe_dump(hunt, sort_keys=False))
        errors = validate_rules.validate_hunting_query(tmp / "dcsync.yaml")
        self.assertTrue(any("differs from" in e for e in errors))

    def test_missing_attack_id_fails(self):
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp)
        hunt = yaml.safe_load((ROOT / "hunting" / "dcsync.yaml").read_text())
        hunt["relevantTechniques"] = []
        (tmp / "dcsync.yaml").write_text(yaml.safe_dump(hunt, sort_keys=False))
        self.assertTrue(validate_rules.validate_hunting_query(tmp / "dcsync.yaml"))


class OutputColumnParsing(unittest.TestCase):
    def test_unaliased_function_arguments_are_not_counted(self):
        q = "SecurityEvent\n| project Requester, Blob = pack('ip', SourceIp, 'host', Computer)"
        self.assertEqual(validate_rules.output_columns(q), {"Requester", "Blob"})

    def test_multi_line_project_keeps_all_columns(self):
        q = "SecurityEvent\n| project\n    StartTime,\n    SourceIp,\n    Computer"
        self.assertEqual(validate_rules.output_columns(q), {"StartTime", "SourceIp", "Computer"})

    def test_let_statements_before_the_pipeline_are_ignored(self):
        q = "let x = 3;\nSecurityEvent | project A, B"
        self.assertEqual(validate_rules.output_columns(q), {"A", "B"})


class ValidatorRejectsBrokenRules(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        shutil.copytree(ROOT / "detections" / "kerberoasting", self.tmp / "detections" / "kerberoasting")
        self.rule_path = self.tmp / "detections" / "kerberoasting" / "rule.yaml"

    def mutate(self, change):
        rule = yaml.safe_load(self.rule_path.read_text())
        change(rule)
        self.rule_path.write_text(yaml.safe_dump(rule, sort_keys=False))
        return validate_rules.validate_rule(self.rule_path)

    def test_every_required_field_is_enforced(self):
        original = self.rule_path.read_text()
        for field in validate_rules.REQUIRED_FIELDS:
            self.rule_path.write_text(original)
            with self.subTest(field=field):
                errors = self.mutate(lambda rule, f=field: rule.pop(f))
                self.assertIn(f"missing required field '{field}'", errors)

    def test_missing_attack_id_fails(self):
        self.assertTrue(self.mutate(lambda rule: rule.update(relevantTechniques=[])))

    def test_malformed_attack_id_fails(self):
        errors = self.mutate(lambda rule: rule.update(relevantTechniques=["Kerberoasting"]))
        self.assertTrue(any("ATT&CK" in e for e in errors))

    def test_empty_query_fails(self):
        self.assertTrue(self.mutate(lambda rule: rule.update(query="   ")))

    def test_query_drift_from_kql_file_fails(self):
        errors = self.mutate(lambda rule: rule.update(query=rule["query"] + "\n| take 1"))
        self.assertIn("query in rule.yaml differs from query.kql", errors)

    def test_unmapped_entity_column_fails(self):
        def change(rule):
            rule["entityMappings"][0]["fieldMappings"][0]["columnName"] = "NoSuchColumn"
        self.assertTrue(any("NoSuchColumn" in e for e in self.mutate(change)))

    def test_entity_mapped_to_a_function_argument_only_fails(self):
        # SourceIp appears only inside a pack() in the final project, not as an output column.
        def change(rule):
            q = rule["query"].rstrip()
            rule["query"] = q + "\n| project Requester, Detail = pack('ip', SourceIp)"
            (self.rule_path.with_name("query.kql")).write_text(rule["query"])
            rule["entityMappings"] = [{"entityType": "IP", "fieldMappings": [{"identifier": "Address", "columnName": "SourceIp"}]}]
        self.assertTrue(any("SourceIp" in e for e in self.mutate(change)))

    def test_customdetails_as_a_list_does_not_crash(self):
        errors = self.mutate(lambda rule: rule.update(customDetails=["Requester"]))
        self.assertTrue(any("customDetails must be a mapping" in e for e in errors))

    def test_main_survives_a_malformed_rule(self):
        self.rule_path.write_text("entityMappings: not-a-list\nid: 1\n")
        # Must return a failure code, not raise.
        self.assertEqual(validate_rules.main(["validate_rules.py", str(self.tmp)]), 1)

    def test_entity_column_named_only_in_a_comment_fails(self):
        # RawUser is used inside the query but is not in its final project.
        def change(rule):
            rule["entityMappings"][0]["fieldMappings"][0]["columnName"] = "RawUser"
        self.assertTrue(any("RawUser" in e for e in self.mutate(change)))

    def test_custom_detail_column_not_in_output_fails(self):
        errors = self.mutate(lambda rule: rule.update(customDetails={"Enc": "EncType"}))
        self.assertTrue(any("customDetails column 'EncType'" in e for e in errors))

    def test_period_shorter_than_frequency_fails(self):
        errors = self.mutate(lambda rule: rule.update(queryFrequency="1h", queryPeriod="30m"))
        self.assertTrue(any("queryPeriod is shorter" in e for e in errors))

    def test_main_fails_on_broken_rule(self):
        self.mutate(lambda rule: rule.pop("severity"))
        self.assertEqual(validate_rules.main(["validate_rules.py", str(self.tmp)]), 1)


class SchemaFile(unittest.TestCase):
    def test_columns_absent_from_the_real_table_are_not_listed(self):
        schema = (ROOT / "scripts" / "securityevent.schema").read_text()
        names = {l.split(":")[0].strip() for l in schema.splitlines() if l.strip() and not l.startswith("#")}
        self.assertFalse(names & {"TicketEncryptionType", "TicketOptions"})


class ArmConversion(unittest.TestCase):
    def test_timespans(self):
        self.assertEqual(yaml_to_arm.iso8601("30m"), "PT30M")
        self.assertEqual(yaml_to_arm.iso8601("12h"), "PT12H")
        self.assertEqual(yaml_to_arm.iso8601("1d"), "P1D")
        with self.assertRaises(ValueError):
            yaml_to_arm.iso8601("soon")

    def test_template_holds_every_rule_disabled_and_no_identifiers(self):
        template = yaml_to_arm.build_template(ROOT)
        self.assertEqual(len(template["resources"]), len(list((ROOT / "detections").glob("*/rule.yaml"))))
        for resource in template["resources"]:
            self.assertEqual(resource["kind"], "Scheduled")
            self.assertFalse(resource["properties"]["enabled"])
            self.assertEqual(resource["properties"]["triggerOperator"], "GreaterThan")
            self.assertTrue(all("." not in t for t in resource["properties"]["techniques"]))
        self.assertNotIn("/subscriptions/", str(template))


if __name__ == "__main__":
    unittest.main()
