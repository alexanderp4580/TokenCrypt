# Co-author trailer hooks

These hooks remove `Co-Authored-By` trailers from commit messages, including messages supplied with `git commit -m` and messages reused by `git commit --amend --no-edit`.

Enable them in a clone with:

```sh
git config core.hooksPath .githooks
```

Python 3 must be available. Both hooks call the shared sanitizer: `prepare-commit-msg` cleans the initial message and `commit-msg` cleans the final message after editing. Other message text and trailers remain intact. Removing all trailing co-author lines leaves one final newline; CRLF input is retained.

Git hooks are a local safeguard. `git commit --no-verify` skips the final `commit-msg` check; `prepare-commit-msg` still cleans the initial message, but trailers added afterward can remain. Overriding `core.hooksPath` or using commit plumbing can bypass both hooks. ([Git hook documentation](https://git-scm.com/docs/githooks))

Run the focused tests from the repository root with:

```sh
python3 -B -m unittest discover -s .githooks/tests -v
```
