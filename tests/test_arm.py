import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

from tools import arm, build_arm, catalog, lint, watchlists


class Literal(unittest.TestCase):
    def test_bracketed_content_is_escaped(self):
        self.assertEqual(arm.literal("[listKeys('x')]"), "[[listKeys('x')]")
        self.assertEqual(arm.literal("[Lab] Kerberoasting [T1558]"), "[[Lab] Kerberoasting [T1558]")

    def test_other_strings_are_unchanged(self):
        for value in ("plain", "[not closed", "closed]", "a [b] c", ""):
            with self.subTest(value=value):
                self.assertEqual(arm.literal(value), value)

    def test_nested_values_are_escaped(self):
        self.assertEqual(
            arm.literal({"a": ["[x]", 1, {"b": "[y]"}]}), {"a": ["[[x]", 1, {"b": "[[y]"}]}
        )


class TemplateContent(unittest.TestCase):
    def test_rule_text_cannot_become_an_expression(self):
        rule = catalog.load_yaml(catalog.REPO_ROOT / "detections/dcsync/analytic.yaml")
        rule["name"] = "[concat('a', 'b')]"
        resource = build_arm.to_resource(rule)
        self.assertEqual(resource["properties"]["displayName"], "[[concat('a', 'b')]")
        # The template's own expression is still an expression.
        self.assertEqual(resource["properties"]["enabled"], "[parameters('enableRules')]")

    def test_rule_id_must_be_safe_in_a_resource_name(self):
        rule = catalog.load_yaml(catalog.REPO_ROOT / "detections/dcsync/analytic.yaml")
        rule["id"] = "x')]"
        with self.assertRaises(ValueError):
            build_arm.to_resource(rule)


class Aliases(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        shutil.copytree(catalog.REPO_ROOT / "watchlists", self.root / "watchlists")
        index = self.root / "watchlists" / watchlists.INDEX_FILE
        entries = yaml.safe_load(index.read_text())
        entries[0]["alias"] = "x', 'y"
        index.write_text(yaml.safe_dump(entries, sort_keys=False))

    def test_linter_rejects_an_unsafe_alias(self):
        errors = lint.lint_watchlists(self.root, {"dcsync"})["watchlists/watchlists.yaml"]
        self.assertTrue(any("must match" in e for e in errors))

    def test_build_refuses_an_unsafe_alias(self):
        with self.assertRaises(ValueError):
            watchlists.to_resource(watchlists.load(self.root)[0])


if __name__ == "__main__":
    unittest.main()
