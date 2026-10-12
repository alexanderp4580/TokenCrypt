# DOX framework

- Agent must follow DOX instructions across any edits

## Core Contract

- AGENTS.md files are binding work contracts for their subtrees
- Work products, source materials, instructions, records, assets, and durable docs must stay understandable from the nearest applicable AGENTS.md plus every parent AGENTS.md above it

## Read Before Editing

1. Read the root AGENTS.md
2. Identify every file or folder you expect to touch
3. Walk from the repository root to each target path
4. Read every AGENTS.md found along each route
5. If a parent AGENTS.md lists a child AGENTS.md whose scope contains the path, read that child and continue from there
6. Use the nearest AGENTS.md as the local contract and parent docs for repo-wide rules
7. If docs conflict, the closer doc controls local work details, but no child doc may weaken DOX

Do not rely on memory. Re-read the applicable DOX chain in the current session before editing.

## Update After Editing

Every meaningful change requires a DOX pass before the task is done.

Update the closest owning AGENTS.md when a change affects:

- purpose, scope, ownership, or responsibilities
- durable structure, contracts, workflows, or operating rules
- required inputs, outputs, permissions, constraints, side effects, or artifacts
- user preferences about behavior, communication, process, organization, or quality
- AGENTS.md creation, deletion, move, rename, or index contents

Update parent docs when parent-level structure, ownership, workflow, or child index changes. Update child docs when parent changes alter local rules. Remove stale or contradictory text immediately. Small edits that do not change behavior or contracts may leave docs unchanged, but the DOX pass still must happen.

## Hierarchy

- Root AGENTS.md is the DOX rail: project-wide instructions, global preferences, durable workflow rules, and the top-level Child DOX Index
- Child AGENTS.md files own domain-specific instructions and their own Child DOX Index
- Each parent explains what its direct children cover and what stays owned by the parent
- The closer a doc is to the work, the more specific and practical it must be

## Child Doc Shape

- Create a child AGENTS.md when a folder becomes a durable boundary with its own purpose, rules, responsibilities, workflow, materials, or quality standards
- Work Guidance must reflect the current standards of the project or user instructions; if there are no specific standards or instructions yet, leave it empty
- Verification must reflect an existing check; if no verification framework exists yet, leave it empty and update it when one exists

Default section order:
- Purpose
- Ownership
- Local Contracts
- Work Guidance
- Verification
- Child DOX Index

## Style

- Keep docs concise, current, and operational
- Document stable contracts, not diary entries
- Put broad rules in parent docs and concrete details in child docs
- Prefer direct bullets with explicit names
- Do not duplicate rules across many files unless each scope needs a local version
- Delete stale notes instead of explaining history
- Trim obvious statements, repeated rules, misplaced detail, and warnings for risks that no longer exist

## Closeout

1. Re-check changed paths against the DOX chain
2. Update nearest owning docs and any affected parents or children
3. Refresh every affected Child DOX Index
4. Remove stale or contradictory text
5. Run existing verification when relevant
6. Report any docs intentionally left unchanged and why

## User Preferences

When the user requests a durable behavior change, record it here or in the relevant child AGENTS.md

- TokenCrypt is a local tool for sharing tokens and secrets between the user and a coding agent: secrets stay encrypted until the user grants time-limited access
- The user manages secrets through a website; the agent uses a CLI that can read granted secrets, request access and flag a secret as leaked or invalid, but cannot grant, unlock, create, update, delete or clear flags
- Token expiry is informational civil-date metadata. Existing tokens show Never; the website offers presets from 1 day through 2 years and a custom date picker. Expiry edits preserve token values and grant policy.
- The website uses a dark Pico theme; styling rules are in `docs/design.md` under Web UI.
- Write only what was requested or verified; check file, API, dependency and licence claims before writing them; mark unchecked items "to check"; no filler or invented items
- Re-read a whole doc after editing it and fix contradictions
- Hard rule: no tombstones. Docs, comments and commit content describe only what exists now; never mention removed, replaced or no-longer-used things
- Never add co-author trailers to commits. Before committing in a fresh clone, run `git config core.hooksPath .githooks`; both commit-message hooks strip co-author trailers.
- Never put real secrets in the repository, tests, docs, logs or commit messages; tests use fake values
- Keep communication concise; state results and blockers directly. Post progress updates during execution; finish authorized work without routine questions.
- On an explicit stop, interrupt project workers and update the progress checkpoint. Resume implementation or background orchestration only after an explicit user instruction.
- Ask clarifying questions one at a time (Claude Code: `AskUserQuestion`; Codex: `request_user_input_async`) until the relevant user requirements are known. Resolve routine technical choices independently when project requirements provide enough information.
- Superpowers and stop-slop are installed for both agents. Codex: `~/.codex/skills/`. Claude Code: Superpowers as the `superpowers@claude-plugins-official` plugin; stop-slop as a mirrored copy in `~/.claude/skills/stop-slop/`. Use them through the Development workflow below, with the agreed single-slice approval and targeted prose editing
- Delegate scoped research, drafting, implementation, and review to cheaper agents. Give each clear ownership, context, and acceptance criteria; the primary agent coordinates and integrates.
- Use available agents suited to implementation and independent review, including equivalent non-Sonnet agents. Prefer economical models and focused contexts; preserve tokens.
- Preserve tokens. Plans state task order, interfaces, test assertions, fixed constraints and commands with expected results; they do not contain implementation code. The primary agent never writes the implementation itself; workers write it test-first. This overrides skill defaults that ask for complete code in plans.
- The user authorized autonomous execution of Slices A–D through a running website. Complete the existing plan without intermediate approval questions. Merging to `main` needs user approval.
- Hosting is local first: the daemon and website run on the user's device behind an optional reverse proxy; plain HTTP uses approval links and cookies without the Secure flag. Telegram carries approval requests.

## Development workflow

Read the applicable installed `SKILL.md` at the stage where it applies, plus any referenced template or material needed for that action. Codex reads skills from `~/.codex/skills/<name>/`; Claude Code invokes them with the Skill tool (Superpowers names carry the `superpowers:` prefix). Announce first use briefly. User instructions and this project's agreed approval/prose rules take precedence over conflicting skill defaults. Load relevant skills, not the entire collection for each task.

| Stage | Skills |
|---|---|
| Start and understand intent | `using-superpowers`, `brainstorming` |
| Prepare a multi-step implementation plan | `writing-plans` |
| Execute delegated tasks | `subagent-driven-development` |
| Parallel independent tasks | `dispatching-parallel-agents` |
| Implement behavior; investigate failures | `test-driven-development`, `systematic-debugging` |
| Request review; assess feedback | `requesting-code-review`, `receiving-code-review` |
| Check isolation; finish a verified branch | `using-git-worktrees`, `finishing-a-development-branch` |
| Claim completion; edit prose | `verification-before-completion`, `stop-slop` |

Use `executing-plans` for inline execution only if requested or delegation is unavailable. Use `writing-skills` when creating or changing a skill. Do not modify global agent settings as part of a project task.

### Scope and plan

Classify work as a research spike, a bounded change to an existing flow, or architectural work. State intent, constraints, and observable success; distinguish confirmed requirements from proposals. For architectural or multi-step work, prepare a design and a task plan with a linked spec, exact file responsibilities, interfaces, dependencies, fixed constraints, test assertions, commands, and expected results. Check for ambiguity, missing requirements, and unnecessary layers. Use checkboxes for tasks and name the behavior each task proves. Group setup and docs with their tested deliverable; split tasks where independent review is useful. A small existing-flow change needs only a concise design and checks.

Present the concrete slice design, planned work, and acceptance criteria together for one user approval. Then execute within that scope without repeated approval gates. Re-ask for scope changes or required permissions. Each product slice needs its own scope approval.

### Delegation and workspace

Inspect Git status, branch, and worktree state before changes. Reuse existing isolation; use `using-git-worktrees` when feature isolation is needed. Include the intended workspace and branch in the slice approval packet. Start product implementation on `main`/`master` only with explicit consent for that branch. Preserve unrelated edits and establish the relevant baseline. Documentation-only work may stay in the existing checkout. Do not reset, clean, merge, publish, or discard user work without authorization.

Give cheaper workers clean, bounded contexts: task/spec text, relevant DOX chain, owned files, interfaces, constraints, acceptance checks, and required output. Set model and reasoning effort explicitly from the live allowed choices. Keep dependent tasks sequential; parallelize only independent work without shared writes. Reuse the responsible worker for fixes. The coordinator integrates results and checks the final tree rather than treating a worker's success report as proof.

### Tests and debugging

For behavior changes, write a focused behavior test, run it to observe the intended failure, implement the minimum fix, rerun it, then refactor with checks green. Add regression tests for reproduced bugs. Prefer real behavior and boundary fakes over tests that mirror implementation. Verify docs and configuration with relevant checks instead of inventing unit tests. Add dependencies and abstractions when current behavior needs them.

For unexpected behavior, reproduce it, inspect evidence and recent changes, trace the cause, and test one hypothesis with one small change. Avoid bundles of speculative fixes. Repeated failed fixes require examining the design and reporting the evidence before expanding scope.

### Review and evidence

The user requested faster completion on 2026-10-10: skip remaining per-task review gates and documentation polish. Finish runtime integration and essential final automated/browser checks before deployment.

After each delegated implementation task, obtain one independent review covering requirements and code quality. Re-review a fix only when the review found Critical or Important defects, and scope it to the fix diff. Run one whole-branch review at the end. Supply the spec, task, precise diff or commit range, constraints, and observed checks without the coordinator's full conversation. Reviewers work read-only and do not dispatch more agents. Resolve unclear feedback before changing dependent code; validate suggestions against code and prior project decisions, and push back with evidence when they conflict. Fix critical and important defects before advancing; recheck the affected behavior. Record minor follow-ups.

Run fresh, relevant local checks on the final integrated tree before claiming success. Record commands, exit status, and observed results as passed, failed, or not run with reasons. Check acceptance criteria individually; distinguish builds, automated tests, manual checks in the web UI and CLI, and user approval. CI is deferred. Required failed or unrun local checks keep the slice incomplete. After implementation, use `finishing-a-development-branch` to handle integration within existing authorization; preserve a branch when integration is not authorized.

### Documentation and handoff

Update the owning DOX contracts and indexes, reread whole changed documents, and check their links and agreement. Use `stop-slop` and its references for targeted editing of documentation and UI copy: remove filler, vague claims, and formulaic prose; retain technical meaning, factual qualifiers, uncertainty, and exact values. Keep one canonical copy of each contract. Report changed files, verification evidence, and remaining gaps in a short handoff.

## Child DOX Index

- `.githooks/AGENTS.md`: commit-message hooks, setup and focused Git tests
- `docs/AGENTS.md`: design spec and planning documents; owns planning and spec rules
- `toolchain/AGENTS.md`: pinned Go container, `build`, `run` and `check` wrappers
- `cmd/AGENTS.md`: `tokencrypt` executable entry point
- `internal/AGENTS.md`: private Go packages (clock, crypto, vault and subsequent service packages)
- `scripts/AGENTS.md`: executable fake-secret integration checks

Root owns: project-wide rules above, `go.mod` (module `tokencrypt`), `README.md` (short project intro and links) and `CLAUDE.md` (imports this file for Claude Code). Each code boundary gets its own AGENTS.md when it is created.
