# Purpose

Provide repo-contained Git hooks that remove co-author trailers from new and amended commit messages.

# Ownership

This `.githooks` folder owns the Git hooks, setup instructions, and their temporary-repository tests.

# Local Contracts

- Both Git hook phases use `.githooks/sanitize_message.py`.
- Preserve unrelated message text and trailers; remove co-author trailer lines case-insensitively, including space or hyphen separators.
- Hook failure must stop the commit with a useful error.
- `--no-verify` skips `commit-msg`; it does not skip `prepare-commit-msg`. Overriding the hook path or using commit plumbing can bypass both.

# Work Guidance

Use only Python 3 standard-library functionality. Keep message stripping in the shared sanitizer and verify both hook phases with temporary repositories.

# Verification

Run `python3 -B -m unittest discover -s .githooks/tests -v` from the repository root.

# Child DOX Index

No child instruction files.
