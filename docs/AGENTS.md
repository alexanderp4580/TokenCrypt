# docs

## Purpose

- Design and planning documents for TokenCrypt

## Ownership

- `design.md`: intent, decisions, components, cryptography, vault layout, secret management, flags, grants, CLI, web UI, Telegram, audit log, threat model, acceptance criteria and open items
- `implementation-plan.md`: slices, tasks, interfaces, test assertions and commands for building `design.md`
- `evidence.md`: observed verification results by code snapshot and runner, including pending checks
- `progress.md`: current execution state, hosting state and open checks

## Local Contracts

- Items the user has not approved are labelled proposals; unverified claims are marked "to check"
- Cryptographic choices and parameters are verified against primary documentation before they are written as fact
- `design.md` and the code agree; a changed contract is changed in both in the same slice

## Work Guidance

- Follow the root [Development workflow](../AGENTS.md#development-workflow)
- Plans contain interfaces, test assertions, constraints and commands, not implementation code
- Use fake values for secrets in every example

## Verification

- Reread whole changed documents; check links, DOX ownership and agreement between documents
- Run `git diff --check` and inspect untracked documents before reporting completion

## Child DOX Index

No child instruction files.
