import unittest

from tools import build_arm, catalog


class Timespans(unittest.TestCase):
    def test_conversion(self):
        self.assertEqual(build_arm.iso8601("30m"), "PT30M")
        self.assertEqual(build_arm.iso8601("65m"), "PT65M")
        self.assertEqual(build_arm.iso8601("12h"), "PT12H")
        self.assertEqual(build_arm.iso8601("1d"), "P1D")

    def test_rejects_unknown_format(self):
        with self.assertRaises(ValueError):
            build_arm.iso8601("soon")


class Template(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.template = build_arm.build_template()
        cls.resources = cls.template["resources"]

    def test_one_disabled_scheduled_rule_per_detection(self):
        self.assertEqual(len(self.resources), len(catalog.detection_dirs()))
        for resource in self.resources:
            self.assertEqual(resource["kind"], "Scheduled")
            self.assertFalse(resource["properties"]["enabled"])
            self.assertEqual(resource["properties"]["triggerOperator"], "GreaterThan")

    def test_techniques_are_parent_ids(self):
        for resource in self.resources:
            for technique in resource["properties"]["techniques"]:
                self.assertRegex(technique, r"^T\d{4}$")

    def test_alert_title_override_is_carried_over(self):
        for resource in self.resources:
            self.assertIn("alertDisplayNameFormat", resource["properties"]["alertDetailsOverride"])

    def test_contains_no_environment_identifiers(self):
        text = str(self.template)
        self.assertNotIn("/subscriptions/", text)
        self.assertEqual(list(self.template["parameters"]), ["workspace"])


if __name__ == "__main__":
    unittest.main()
