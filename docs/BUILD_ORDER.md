# Build order

Each slice: plan, failing tests, implement, verify, review, PR, explain gate. PRD section 17 rows become named tests, with the row cited in a comment.

0. Foundation (done): project, compose, env config, health.
1. Migrations and schema: five tables, enums as text with check constraints, unique (provider, event_id), receipt query indexes, giveaway_logs, 30 day housekeeping. Propose Flyway and ask for confirmation.
2. Startup guard and typed config. CRITICAL REVIEW. Environment is an enum. Four tests: dev+sandbox starts, staging+live refuses, production+sandbox refuses, production+live starts. Exact URL comparison, never substring.
3. Auth. CRITICAL REVIEW. JWT in HttpOnly Secure SameSite=Strict cookie, 15 minute access token, 7 day single use refresh token with familyId, rotation, reuse detection revokes the family, Redis revoked set with 15 minute TTL, database written before Redis, resolve endpoints fail closed with 503 when Redis is down.
4. Quota. CRITICAL REVIEW. claimRoll as one conditional UPDATE, refundRoll as SQL decrement. Concurrency test: many threads, one roll left, exactly one success, rolls_used never exceeds rolls_allocated.
5. Create giveaway: validation (PRD section 5, all rejections before any external call), 402 with no roll, synchronous Apify ingestion with CompletableFuture.allOf, failure classification, refund on failure, retweet required rule.
6. Cleaning pipeline: truncate to 500 chars, chain isolated extraction, order by timestamp then replyId as Long, dual key dedup, precedence order. Streamed bulk insert. Never load all entries as objects. (Can run in parallel with 3 in a separate worktree once slice 1 is merged.)
7. Selection and verification rounds: shortlist size, parallel follow checks, unresolved versus failed, 800 ms timeout, 400 ms gap, up to 3 retries, backup pulls, shortfall state.
8. State machine and resolve endpoints. CRITICAL REVIEW. Two distinct AWAITING states, row lock plus status recheck inside the lock, strict deadline comparison, 404 identical body, 409 for wrong state or elapsed deadline, timeout default leaves the slot empty.
9. Finalization, public receipt (/r/:slug, three aggregation queries, Check My Entry with ordered LIMIT 1, 410 at finalized plus 720h), streamed CSV export, List My Giveaways. One shared 30 day check.
10. Bachs webhook. CRITICAL REVIEW. Verify header names in sandbox first. Signature verification, unique (provider, event_id) in the database, duplicate returns 200, addRolls on success.
11. Release (devops agent): Dockerfile on Java 25, CI, release candidate workflow, staging deploy, prove the startup guard fires on a wrong staging URL, liveness health check path.
