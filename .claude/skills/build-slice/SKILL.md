---
name: build-slice
description: Build one slice of the giveaway engine through the full pipeline (plan, failing tests, implement, review, PR, explain gate).
disable-model-invocation: true
---
Build slice $ARGUMENTS following this pipeline exactly. Do not skip or reorder steps.

1. Read docs/BUILD_ORDER.md for slice $ARGUMENTS and read only the PRD sections it needs (docs/PRD.md). Confirm the previous slice is merged to main. Run `git fetch origin`, then create branch `slice-$ARGUMENTS-<short-name>` with `git switch -c slice-$ARGUMENTS-<short-name> origin/main`. Never check out main itself: the session may run in a worktree where main is already checked out elsewhere.
2. PLAN. Write docs/slices/<NN>-<name>.md: tables and constraints, endpoints and status codes, the failure cases (race, timeout, duplicate, crash, bad input), the tests you will write with PRD section 17 rows cited, and the logs and metrics to add. STOP and wait for Adedotun's approval or edits.
3. RED. Use the test-engineer subagent to write the failing tests only. Run them and show the failures. Do not write implementation yet.
4. GREEN. Implement the minimum code to pass. Run `./mvnw -B verify` and show the output.
5. REVIEW. Use the reviewer subagent on the diff against the slice doc and the PRD. Fix correctness and requirement gaps only. Run verify again.
6. If the slice is marked CRITICAL REVIEW, or touches auth, webhooks, or the resolve endpoints, also use the security-reviewer subagent and fix its findings.
7. OBSERVABILITY. Confirm giveawayId MDC, giveaway_logs events and metrics exist for the new paths, and that each failure test asserts them.
8. Update the slice doc with decisions made and the failure modes covered. Commit with a descriptive message and open a pull request with `gh pr create`. Do not merge.
9. EXPLAIN GATE. Ask Adedotun three questions about this slice's failure modes, one at a time, and wait for each answer. If an answer is vague, say so and ask again. Do not start another slice.
