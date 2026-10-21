# Giveaway Trust Engine

Spec: docs/PRD.md (source of truth, approved Oct 16, 2026). Build order: docs/BUILD_ORDER.md. If code and PRD disagree, stop and ask. Never change PRD behavior silently.

Stack: Java 25, Spring Boot 4.1.1, Maven wrapper (./mvnw), Postgres, Redis (noeviction), Testcontainers, WireMock, Sentry, Micrometer. Package com.giveaway.giveawaytrustengine.

## Commands
* Unit tests: `./mvnw -q -B test`
* Full check, run before any PR: `./mvnw -B verify` (needs Docker running)

## Workflow
* Use `/build-slice N` for every slice. One slice per branch and pull request. Do not start slice N+1 before slice N is merged.
* Plan first and wait for approval. Failing tests first, shown red. Then implement.
* Show test output as evidence. Never claim a slice is done without a passing `./mvnw -B verify`.
* Do not add dependencies, change Java or Boot versions, or restructure packages without asking.
* Never commit secrets. The repo is public. No defaults for secrets.

## Engineering rules (IMPORTANT)
* userId comes from the JWT, never from request input.
* Every external call has an explicit timeout (database, Redis, Apify, Bachs, Sentry).
* Never hold a transaction or row lock across an external call.
* Every Redis key has a TTL.
* Money and quota math happens in SQL, never read then write in Java.
* Invariants live in database constraints (unique, check, foreign key), not only in code.
* Schema changes only through migrations. ddl-auto stays validate. Never edit an applied migration.
* Time comes from an injected Clock. Never call Instant.now() in business code.
* Config through @ConfigurationProperties records validated at startup. No scattered @Value.
* Never log or return extractedWallet. Redact before logging at every level.
* Status codes follow the PRD: 401, 402, 404 (identical body for missing and not owned), 409, 410, 503.

## Observability (required in every slice)
* Structured JSON logs with giveawayId in the MDC, plus a requestId per request.
* Pipeline events persisted to giveaway_logs (PRD section 14), with a terminal outcome line per giveaway.
* Micrometer counters and timers for the events the slice introduces. Liveness path for platform health checks.
* Each failure test also asserts the log line or metric an operator would see.

## CRITICAL REVIEW slices
Startup guard, auth, quota claim, resolve endpoints with lock and recheck, Bachs webhook. For these, after implementing, give a line by line walkthrough of the risky parts and name the exact test proving each failure mode.

## Open items: never guess, ask
Bachs webhook header names, retry id reuse, response codes, retry schedule, sandbox and live base URLs; retweet dataset completeness; migration tool; giveaway_logs retention; pool sizes; Render shutdown window.
