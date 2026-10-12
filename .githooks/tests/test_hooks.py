import os
from pathlib import Path
import subprocess
import tempfile
import unittest


HOOKS = Path(__file__).resolve().parents[1]


class CommitHookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.repo = Path(self.temp.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Hook Test")
        self.git("config", "user.email", "hook-test@example.invalid")
        self.git("config", "core.hooksPath", str(HOOKS))
        (self.repo / "file.txt").write_text("one\n")
        self.git("add", "file.txt")

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args, check=True, input=None, env=None):
        return subprocess.run(
            ["git", *args], cwd=self.repo, text=True, capture_output=True,
            check=check, input=input, env=env
        )

    def commit_message(self):
        commit = self.git("cat-file", "commit", "HEAD").stdout
        return commit.split("\n\n", 1)[1]

    def test_commit_message_removes_multiple_case_and_separator_variants(self):
        self.git(
            "commit", "-m",
            "Subject\n\nBody stays\nCo-Authored-By: Alice <a@example.com>\n"
            "cO aUtHoReD bY: Bob <b@example.com>\nCo authored by: Carol <c@example.com>",
        )
        message = self.commit_message()
        self.assertEqual(message, "Subject\n\nBody stays\n")
        self.assertNotIn("authored", message.lower())

    def test_amend_no_edit_removes_existing_trailer(self):
        self.git(
            "-c", "core.hooksPath=/dev/null", "commit", "-m",
            "Subject\n\nCo-Authored-By: Alice <a@example.com>",
        )
        self.assertIn("Co-Authored-By", self.commit_message())
        self.git("commit", "--amend", "--no-edit")
        self.assertEqual(self.commit_message(), "Subject\n")

    def test_commit_msg_removes_trailer_added_by_editor(self):
        editor = self.repo / "editor.py"
        editor.write_text(
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "from pathlib import Path\n"
            "path = Path(sys.argv[1])\n"
            "path.write_text(path.read_text() + '\\nCo-Authored-By: Editor <e@example.com>\\n')\n"
        )
        editor.chmod(0o755)
        env = os.environ.copy()
        env["GIT_EDITOR"] = str(editor)
        result = self.git("commit", "-m", "Subject", "--edit", env=env, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.commit_message(), "Subject\n")

    def test_unrelated_trailers_and_text_are_preserved(self):
        self.git(
            "commit", "-m",
            "Subject\n\nReviewed-by: Reviewer <r@example.com>\nSigned-off-by: Author <a@example.com>",
        )
        self.assertEqual(
            self.commit_message(),
            "Subject\n\nReviewed-by: Reviewer <r@example.com>\nSigned-off-by: Author <a@example.com>\n",
        )

    def test_clean_message_and_second_pass_are_unchanged(self):
        self.git("commit", "-m", "Subject\n\nBody\n")
        before = self.commit_message()
        self.git("commit", "--amend", "--no-edit")
        self.assertEqual(self.commit_message(), before)

    def test_hook_preserves_crlf_when_removing_a_trailer(self):
        message_file = self.repo / "message.txt"
        message_file.write_bytes(
            b"Subject\r\n\r\nBody\r\nCo-Authored-By: A <a@example.com>\r\n"
        )
        subprocess.run(
            [str(HOOKS / "commit-msg"), str(message_file)], check=True, capture_output=True
        )
        self.assertEqual(message_file.read_bytes(), b"Subject\r\n\r\nBody\r\n")

    def test_missing_message_file_fails_with_a_clear_error(self):
        result = subprocess.run(
            [str(HOOKS / "commit-msg"), str(self.repo / "missing-message")],
            text=True, capture_output=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot sanitize message file", result.stderr.lower())


if __name__ == "__main__":
    unittest.main()
