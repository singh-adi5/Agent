import unittest
from datetime import UTC, datetime

from tools.emulator_test import Engine, build_csl, kql_literal

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


class Literals(unittest.TestCase):
    def test_age_becomes_a_timestamp_before_now(self):
        self.assertEqual(kql_literal(5, "datetime", NOW), "datetime(2026-01-01T11:55:00.000000Z)")

    def test_missing_int_is_null(self):
        self.assertEqual(kql_literal(None, "int", NOW), "int(null)")

    def test_strings_are_escaped(self):
        self.assertEqual(kql_literal('CONTOSO\\a"b', "string", NOW), '"CONTOSO\\\\a\\"b"')


class Csl(unittest.TestCase):
    def test_wraps_the_query_with_an_inline_table(self):
        columns = [("TimeGenerated", "datetime"), ("EventID", "int"), ("Computer", "string")]
        csl = build_csl(columns, [{"age_minutes": 1, "EventID": 4769}], "SecurityEvent", NOW)
        self.assertTrue(csl.startswith("let SecurityEvent = datatable(TimeGenerated:datetime"))
        self.assertIn('datetime(2026-01-01T11:59:00.000000Z), int(4769), ""', csl)
        self.assertTrue(csl.endswith("];\nSecurityEvent"))


class EngineUrl(unittest.TestCase):
    def test_only_http_schemes_are_accepted(self):
        with self.assertRaises(ValueError):
            Engine("file:///etc/passwd")


if __name__ == "__main__":
    unittest.main()
