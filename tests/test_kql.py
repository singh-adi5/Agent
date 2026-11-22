import unittest

from tools.kql import output_columns, placeholders, split_top_level, string_literal


class SplitTopLevel(unittest.TestCase):
    def test_ignores_separators_inside_brackets_and_strings(self):
        self.assertEqual(
            split_top_level("a, f(b, c), 'd, e', [g, h]", ","),
            ["a", " f(b, c)", " 'd, e'", " [g, h]"],
        )


class StringLiteral(unittest.TestCase):
    def test_escapes_quotes_backslashes_and_control_characters(self):
        self.assertEqual(string_literal('a"b\\c'), '"a\\"b\\\\c"')
        self.assertEqual(string_literal("GC/a\n\t\tHOST/b\r"), '"GC/a\\n\\t\\tHOST/b\\r"')
        self.assertEqual(string_literal(None), '""')


class OutputColumns(unittest.TestCase):
    def test_aliases_and_bare_names_count(self):
        query = "SecurityEvent\n| project Requester, Count = count(), SourceIp"
        self.assertEqual(output_columns(query), {"Requester", "Count", "SourceIp"})

    def test_identifiers_inside_an_unaliased_call_do_not_count(self):
        query = "SecurityEvent\n| project Requester, pack('ip', SourceIp)"
        self.assertEqual(output_columns(query), {"Requester"})

    def test_multi_line_project(self):
        query = "SecurityEvent\n| project\n    StartTime,\n    SourceIp,\n    Computer"
        self.assertEqual(output_columns(query), {"StartTime", "SourceIp", "Computer"})

    def test_let_statements_and_comments_are_ignored(self):
        query = "let x = 3;\n// | project Hidden\nSecurityEvent | project A, B"
        self.assertEqual(output_columns(query), {"A", "B"})

    def test_last_project_wins(self):
        query = "SecurityEvent | project A, B | where A > 1 | project-reorder B, A"
        self.assertEqual(output_columns(query), {"A", "B"})

    def test_no_project(self):
        self.assertEqual(output_columns("SecurityEvent | take 1"), set())


class Placeholders(unittest.TestCase):
    def test_reads_column_names(self):
        self.assertEqual(placeholders("{{Actor}} from {{ SourceIp }}"), {"Actor", "SourceIp"})


if __name__ == "__main__":
    unittest.main()
