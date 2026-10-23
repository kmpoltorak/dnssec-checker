# AGENTS.md

Rules for AI coding agents working in this repo. Project specifics (purpose, commands,
layout, limitations) live in `README.md`: read it before changing anything.

## Workflow

1. Read the README and the code the change touches first.
2. Non-trivial change: write a short plan (what, why, what can break, how it is tested)
   and wait for approval.
3. Ask, don't guess, when the spec is unclear or the change touches security, auth,
   input validation or secrets.
4. Never commit to `main`. One logical change per branch and PR. Commit prefixes:
   `feat:`, `fix:`, `docs:`, `ci:`, `chore:`.
5. The PR description says what changed, why, and how it was verified.
6. CI must be green before merge. Never skip, weaken or delete a failing test, and never
   add `|| true` to lint, to make it green. Fix the code or ask.

## Minimal code: ponytail (required)

- Use the `ponytail` skill for every coding task.
- Before opening a PR, run `/ponytail-review` on the diff and apply what it finds.
- Mark a deliberate shortcut with a `ponytail:` comment naming the trade-off.
- Never removed for brevity: timeouts, retries, cleanup, validation at trust boundaries,
  error handling that prevents data loss, security checks, secret masking, tests.

## Tests (required)

- Every behavior change ships with a test. No test, not done.
- A test must be able to fail: break the behavior, see the test fail, restore it, and say
  so in the PR (`sabotage check: removed X → test Y failed`).
- Test the failure modes, not only the happy path. Assert observable behavior, not mocks.

## Documentation (required)

- Check the README against every change and update it in the same PR (usage,
  configuration, limitations, testing).
- Every README claim is backed by code or a test. If you cannot point to it, remove it.
- Plain English, no marketing, no invented numbers.

## README format

Follow the layout of remote-command-orchestrator. Short and scannable; target ~200 lines.

1. Title, then 2–4 sentences: what it does and for which conditions.
2. One real example (command + output).
3. 3–5 bullets: the guarantees that matter (safety, validation, failure handling).
4. Install
5. Quick start
6. Reference sections the tool needs (config, usage, API) — tables over prose.
7. Limitations: honest gaps, including anything not yet tested.
8. Development: make targets, one paragraph on how the tests work.
9. One line: "Built with an AI coding assistant. I wrote the spec and reviewed every change."
10. License

No overview, architecture essays, roadmap, contributing, project structure or
technology-stack sections unless a user needs them to run the tool.

## Data and secrets

- Example data only: `example.com` / `example.net`, RFC 5737 addresses.
- No secrets in the repo; provide `.env.example`, read secrets from the environment.

## Definition of done

- [ ] Plan approved, change on a branch, PR opened
- [ ] `/ponytail-review` applied
- [ ] Tests added and sabotage-checked
- [ ] README and docs updated
- [ ] CI green
