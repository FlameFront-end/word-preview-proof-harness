from pathlib import Path
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "shellGenerator.sh"
TEMPLATE_PATH = PROJECT_ROOT / "template.c"


class ShellGeneratorStaticTests(unittest.TestCase):
    def test_template_owns_cmd_char_array_delimiters(self):
        template = TEMPLATE_PATH.read_text(encoding="utf-8")

        self.assertIn("CHAR cmd_c[] = {<CMD>, 0};", template)
        self.assertNotIn("CHAR cmd_c[] = {'<CMD>', 0};", template)

    def test_script_does_not_interpolate_cmd_with_sed(self):
        script = SCRIPT_PATH.read_text(encoding="utf-8")

        self.assertIn("build_cmd_char_array", script)
        self.assertNotIn('sed "s#<CMD>#${CMD}#g"', script)

    def test_script_rejects_unsupported_cmd_characters(self):
        script = SCRIPT_PATH.read_text(encoding="utf-8")

        self.assertIn("validate_cmd", script)
        self.assertIn("single quotes and backslashes are not supported", script)


if __name__ == "__main__":
    unittest.main()
