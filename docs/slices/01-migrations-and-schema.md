# Slice 1: Migrations and schema

PRD refs: Section 3 (Domain Model), Section 14 (Observability), Section 15 (30-day boundary), Section 17 (Payment idempotency row).

## Decision: migration tool

Flyway, confirmed with Adedotun. Plain SQL migrations under `src/main/resources/db/migration`, versioned `V1__*.sql`, `V2__*.sql`, etc. `ddl-auto=validate` is already set in `application.properties` (from slice 0) — Flyway owns schema, Hibernate only validates against it.

Dependencies, verified against Maven Central for Boot 4.1.1 before adding (not guessed): `org.springframework.boot:spring-boot-starter-flyway` (exists starting Boot 4.0.0; pulls in `spring-boot-starter-jdbc` and transitively `flyway-core:12.4.0` via `spring-boot-flyway`) plus `org.flywaydb:flyway-database-postgresql` explicitly — the starter does not pull this in on its own, and Flyway 10+ requires it for Postgres support (the Postgres driver was split out of `flyway-core`).

## Decision: giveaway_logs retention

PRD Section 14/18 explicitly marks this window as *not yet finalized* ("expected to follow a pattern similar to the giveaway data's own 30-day lifecycle" — no locked number). Asked Adedotun directly; no preference given. Per CLAUDE.md ("Open items: never guess, ask" lists `giveaway_logs` retention by name), this slice creates the `giveaway_logs` table only. **No housekeeping/deletion job is implemented in slice 1.** The daily partition-drop job mentioned in Section 15 is for giveaway data, not logs, and is out of scope for this slice regardless. This stays an open item; do not pick a number for it later without Adedotun's sign-off.

## Decision: no partitioning

Plain tables, no partitioning, for every table in this slice including `giveaway_entry` and `giveaway_logs`. Reason: expected volume is a handful of giveaways a month at 1k-5k replies each (Section 18), nowhere near where partitioning earns its complexity. Revisit trigger: if the nightly housekeeping delete (giveaway data's own 30-day/35-day cadence, Section 15) starts taking over 1 minute, or any single table crosses 5 million rows, partitioning gets reconsidered then — not before.

## Tables (migration V1)

Five domain tables from Section 3, plus `payment_event` (required to back the Section 17 idempotency row, see below) and `giveaway_logs` — seven tables total.

### community_manager
| column | type | constraint |
|---|---|---|
| id | uuid | PK |
| email | text | not null, unique |
| x_handle | text | not null, unique |
| created_at | timestamptz | not null |

### account_quota
| column | type | constraint |
|---|---|---|
| id | uuid | PK |
| cm_id | uuid | not null, unique, FK → community_manager(id) |
| rolls_allocated | int | not null, check >= 0 |
| rolls_used | int | not null, check >= 0, check (rolls_used <= rolls_allocated) |

One quota row per CM (1:1), enforced by `unique(cm_id)`. The `rolls_used <= rolls_allocated` check backs the atomic-claim invariant (Section 3/16) at the database level, not just in the `claimRoll()` UPDATE statement — belt-and-suspenders per CLAUDE.md ("Invariants live in database constraints").

### giveaway
| column | type | constraint |
|---|---|---|
| id | uuid | PK |
| cm_id | uuid | not null, FK → community_manager(id) |
| receipt_slug | text | null, unique |
| tweet_id | text | not null |
| chain | text | not null, check in ('EVM','SOLANA') |
| selection_mode | text | not null, check in ('RANDOM','FIRST_N') |
| target_winners | int | not null, check between 1 and 100 |
| status | text | not null, check in ('PENDING_SCRAPE','PROCESSING','AWAITING_SHORTFALL_RESOLUTION','AWAITING_GUARANTEED_RESOLUTION','FINALIZED','FAILED','CANCELED') |
| include_retweets | boolean | not null |
| required_follow_handles | text[] | not null, default '{}' |
| excluded_handles | text[] | not null, default '{}' |
| guaranteed_handles | text[] | not null, default '{}' |
| raw_replies_count | int | not null, default 0 |
| valid_entries_count | int | not null, default 0 |
| failure_reason | text | null, check in ('POST_DELETED','ACCOUNT_PRIVATE','ACTOR_INPUT_ERROR','INGESTION_TIMEOUT','UNKNOWN_INGESTION_ERROR') |
| failed_stage | text | null, check in ('REPLIES','RETWEETS') |
| guaranteed_deadline | timestamptz | null |
| finalized_at | timestamptz | null |
| created_at | timestamptz | not null |

Enums stored as `text` with a `check` constraint per CLAUDE.md ("enums as text with check constraints"). A table-level check constraint enforces `failure_reason`/`failed_stage` are populated only when `status = 'FAILED'` (both null otherwise) — this is the "only ever populated when status = FAILED" rule from Section 3, pushed into the schema instead of trusted to application code alone.

Additional check constraints on `giveaway`:
- `receipt_slug IS NOT NULL` only when `status = 'FINALIZED'` (otherwise null) — Section 10: "The slug itself is generated only at finalization. It does not exist in the database beforehand."
- `(status = 'FINALIZED') = (finalized_at IS NOT NULL)` — the two must agree in both directions: no finalized giveaway without a timestamp, and no timestamp set on a giveaway that isn't finalized.
- `guaranteed_deadline IS NOT NULL` when `status = 'AWAITING_GUARANTEED_RESOLUTION'` — Section 15: the 10-minute deadline is stored the moment the giveaway enters this state, so the state and the deadline can't drift apart.
- `cardinality(guaranteed_handles) <= target_winners` — a giveaway can't guarantee more winners than it targets.
- `guaranteed_handles` and `excluded_handles` must not overlap — enforced with `NOT (guaranteed_handles && excluded_handles)` (array overlap operator); a handle can't be simultaneously guaranteed a win and excluded.
- `raw_replies_count >= 0` and `valid_entries_count >= 0`.

Index: `idx_giveaway_cm_id_status` on `(cm_id, status)` — backs "List My Giveaways" (Section 4) and the 30-day boundary check, both filtered by owner + status.

### giveaway_entry
| column | type | constraint |
|---|---|---|
| id | bigserial | PK |
| giveaway_id | uuid | not null, FK → giveaway(id) ON DELETE CASCADE |
| author_handle | text | not null |
| raw_text | text | not null |
| extracted_wallet | text | null |
| reply_timestamp | timestamptz | not null |
| reply_id | bigint | not null |
| is_eligible | boolean | not null, default true |
| disqualification_code | text | null, check in ('WRONG_CHAIN','DUPLICATE_HANDLE','DUPLICATE_WALLET','HOST_EXCLUSION','FAILED_REPOST','FAILED_FOLLOW_HOST','FAILED_FOLLOW_PARTNER') |
| is_winner | boolean | not null, default false |
| winner_allocation | text | null, check in ('CM_GUARANTEED','RANDOM_SELECTION') |

`reply_id` is `bigint`, matching Section 3's "replyId is...parsed and compared as a Long" directly in the column type, not deferred to a cast at query time.

Additional check constraints on `giveaway_entry`:
- `is_eligible = false` exactly when `disqualification_code IS NOT NULL` (and `is_eligible = true` exactly when it's null) — one boolean/code pair, no drift between them.
- `is_winner = true` exactly when `winner_allocation IS NOT NULL`.
- a winner must be eligible: `NOT (is_winner AND NOT is_eligible)`.

Indexes (per build order "receipt query indexes"), revised:
- `idx_entry_giveaway_winner` on `(giveaway_id, is_winner)` — backs the public receipt's winners list and CSV export (Section 9 aggregation queries).
- `idx_entry_giveaway_order` on `(giveaway_id, reply_timestamp, reply_id)` — backs the deterministic ordering rule (Section 3) used by cleaning/dedup. Does **not** back Check My Entry (corrected from the prior draft) — that query filters by `author_handle`, not timestamp order, and only uses `reply_timestamp` as its `ORDER BY`'s second key with `is_eligible DESC` first (Section 10).
- `idx_entry_giveaway_handle` on `(giveaway_id, author_handle)` — backs "Check My Entry" (Section 10): `WHERE giveaway_id = :id AND author_handle = :handle ORDER BY is_eligible DESC, reply_timestamp ASC LIMIT 1`.

`idx_entry_giveaway_id` (giveaway_id alone) is dropped — redundant with the three composite indexes above, all of which lead with `giveaway_id`, and a plain index on it would only add write overhead on the bulk insert (slice 6) for no query that needs it standalone.

Constraint: `unique(giveaway_id, reply_id)` — the same reply can never be ingested twice for the same giveaway. **Note for slice 6**: the streamed bulk insert must use `ON CONFLICT (giveaway_id, reply_id) DO NOTHING`, not a plain `INSERT`, or a re-run of ingestion (e.g. after a retry) will throw on the duplicate-key violation instead of silently skipping rows already inserted.

### refresh_token
| column | type | constraint |
|---|---|---|
| token_id | uuid | PK |
| family_id | uuid | not null |
| cm_id | uuid | not null, FK → community_manager(id) |
| used | boolean | not null, default false |
| expires_at | timestamptz | not null |

Index: `idx_refresh_token_family_id` on `(family_id)` — backs family-wide revocation on reuse detection (Section 3/9, slice 3).

### payment_event
Not named as a top-level domain class in Section 3, but required to persist `PaymentEvent` (Section 3 Billing Abstraction) and back the Payment Idempotency acceptance row (Section 17): "(provider, eventId) must carry a database-level unique constraint."

| column | type | constraint |
|---|---|---|
| id | uuid | PK |
| provider | text | not null |
| event_id | text | not null |
| cm_id | uuid | not null, FK → community_manager(id) |
| amount_cents | int | not null, check >= 0 |
| rolls_purchased | int | not null, check > 0 |
| status | text | not null, check in ('SUCCEEDED','FAILED') |
| provider_reference | text | null |
| created_at | timestamptz | not null |

Constraint: `unique(provider, event_id)` — this is the exact mechanism Section 17's "Payment idempotency" row requires: a redelivered webhook hits the unique constraint, not application logic, and the handler (slice 10) catches the constraint violation and returns 200.

`status` check values (`SUCCEEDED`/`FAILED`) are a placeholder matching `PaymentEvent.isSuccessful(): boolean` (Section 3) — not sourced from a confirmed Bachs status vocabulary. Flag this for review once the Bachs sandbox is checked (slice 10); if Bachs's real status strings differ, this check constraint needs a migration update then, not a guess now.

## Assumptions and open items (payment_event)

- **How a Bachs webhook maps to a CM is unverified.** The sample payload seen so far carries only `charge_id` and `checkout_id` — no CM identifier. `payment_event.cm_id` as modeled here assumes the webhook handler can resolve a CM from one of those ids, which isn't confirmed. Proposed fix, **not implemented in this migration**: a `checkout_session` table (`provider`, `provider_checkout_id`, `cm_id`, `tier`, `rolls`) created by `createCheckoutSession()` at checkout time, so the webhook looks up `cm_id` by `provider_checkout_id` instead of needing it in the payload. This is deferred to slice 10, pending Bachs sandbox verification (CLAUDE.md: Bachs webhook details are a never-guess item).
- **Whether `unique(provider, provider_reference)` is safe is open.** Only `unique(provider, event_id)` is added in this migration, per the PRD's explicit idempotency requirement. A second unique constraint on `provider_reference` is not added here — it's unclear yet whether Bachs reuses `provider_reference` across legitimately distinct events (e.g. a refund referencing the same charge). Decide after checking Bachs event semantics in slice 10; do not add speculatively now.
- **Flyway needs the Supabase direct connection string, not the pooler, for staging and production.** Flyway's migration runs (advisory locks, DDL) are not reliably compatible with a transaction-mode connection pooler (e.g. Supavisor/PgBouncer in transaction mode) — the pooler can break session-level locking Flyway relies on. This has no effect on local dev (plain Postgres via compose, no pooler in front of it) but must be confirmed before slice 11 (Release/staging deploy): the datasource URL used for migration needs to be the direct connection, while the application's runtime connection pool can stay on the pooler. Not yet verified against the actual Supabase project; flag before staging.

### giveaway_logs
Section 14: "Every meaningful pipeline event gets a log line... every line for a given giveaway carries the same giveawayId."

| column | type | constraint |
|---|---|---|
| id | bigserial | PK |
| giveaway_id | uuid | null (some events, e.g. payment webhook, have no giveaway) |
| request_id | text | null |
| event_type | text | not null |
| detail | jsonb | not null, default '{}' |
| created_at | timestamptz | not null |

Index: `idx_logs_giveaway_id` on `(giveaway_id)` — "a single roll's full story can be pulled and read in order" (Section 14); combined with `created_at` for ordering: `idx_logs_giveaway_id_created_at` on `(giveaway_id, created_at)`.

No retention/deletion job in this slice (see decision above).

## Failure cases covered by this slice

Schema-only slice — no runtime code paths yet, so "failure cases" here means constraint violations the database itself must reject, proven by tests that attempt the violation and assert it's rejected:

1. **Duplicate payment event** — inserting two `payment_event` rows with the same `(provider, event_id)` violates the unique constraint (backs PRD 17 "Payment idempotency").
2. **Quota overdraw** — inserting/updating `account_quota` so `rolls_used > rolls_allocated` violates the check constraint (backs PRD 3/16/17 "Atomic quota claim").
3. **Orphan rows rejected** — inserting a `giveaway_entry`, `giveaway`, `account_quota`, `refresh_token`, or `payment_event` with a non-existent parent id violates the FK constraint.
4. **Invalid enum value rejected** — inserting a `giveaway` with `status = 'BOGUS'` (or any enum column with an out-of-set text value) violates the check constraint.
5. **Failure fields without FAILED status rejected** — inserting a `giveaway` with `failure_reason` set but `status != 'FAILED'` violates the cross-column check constraint (backs PRD 3 "only ever populated when status = FAILED").
6. **Duplicate CM email/handle rejected** — inserting two `community_manager` rows with the same email or x_handle violates the unique constraints.
7. **Second quota row for same CM rejected** — inserting a second `account_quota` row with the same `cm_id` violates the unique constraint (backs the 1:1 relationship in Section 3).
8. **Receipt slug before finalization rejected** — inserting/updating a `giveaway` with `receipt_slug` set but `status != 'FINALIZED'` violates the check constraint (backs PRD 10).
9. **Finalized giveaway without a slug rejected** — updating a `giveaway` to `status = 'FINALIZED'` with `receipt_slug` still null violates the check constraint.
10. **Duplicate receipt slug rejected** — inserting two `giveaway` rows with the same non-null `receipt_slug` violates the unique constraint.
11. **target_winners out of range rejected** — inserting a `giveaway` with `target_winners = 0` and with `target_winners = 101` each violate the check constraint.
12. **Too many guaranteed handles rejected** — inserting a `giveaway` with `cardinality(guaranteed_handles) > target_winners` violates the check constraint.
13. **Guaranteed/excluded overlap rejected** — inserting a `giveaway` with the same handle in both `guaranteed_handles` and `excluded_handles` violates the check constraint (backs PRD 17 "Input validation, handle conflict" at the schema level).
14. **Eligibility/disqualification drift rejected** — inserting a `giveaway_entry` with `is_eligible = true` and `disqualification_code` set (and the inverse: `is_eligible = false` with a null code) each violate the check constraint.
15. **Winner flag/allocation drift rejected** — inserting a `giveaway_entry` with `is_winner = true` and `winner_allocation` null (and the inverse) each violate the check constraint.
16. **Ineligible winner rejected** — inserting a `giveaway_entry` with `is_winner = true` and `is_eligible = false` violates the check constraint.
17. **Negative/zero payment amounts rejected** — inserting a `payment_event` with `amount_cents = -1` or `rolls_purchased = 0` each violate their check constraints.
18. **Invalid payment status rejected** — inserting a `payment_event` with `status = 'BOGUS'` violates the check constraint.
19. **Cascade delete** — deleting a `giveaway` row that has `giveaway_entry` children deletes those children too (`ON DELETE CASCADE`), proven by inserting a giveaway + entries, deleting the giveaway, and asserting the entries are gone rather than raising an FK violation.
20. **Finalized without finalized_at rejected** — inserting/updating a `giveaway` with `status = 'FINALIZED'` and `finalized_at` null violates the check constraint; the inverse (`finalized_at` set, `status != 'FINALIZED'`) also violates it.
21. **Guaranteed resolution without deadline rejected** — inserting/updating a `giveaway` with `status = 'AWAITING_GUARANTEED_RESOLUTION'` and `guaranteed_deadline` null violates the check constraint.
22. **Negative counters rejected** — inserting a `giveaway` with `raw_replies_count = -1` or `valid_entries_count = -1` each violate their check constraints.
23. **Duplicate (giveaway_id, reply_id) rejected** — inserting two `giveaway_entry` rows with the same `(giveaway_id, reply_id)` violates the unique constraint (backs the slice 6 dedup note above).

No race/timeout/crash cases apply yet — those land in slices 2-10 once there's code making claims, calls, and transactions against this schema.

## Tests (PRD section 17 rows cited above)

Testcontainers-backed `@SpringBootTest` (or a lighter JDBC-only test if a full context isn't needed) against a real Postgres, asserting each failure case above throws a `DataIntegrityViolationException` (or the raw SQLSTATE if done at the JDBC level), plus one happy-path test per table inserting a minimal valid row successfully. Flyway runs automatically on context start against the Testcontainers Postgres — this doubles as the migration's own correctness test (migration fails to apply = test suite fails to start). One test per failure case enumerated above (23 total), plus happy-path inserts for all seven tables, plus one explicit migration test: Flyway applies `V1` cleanly to an empty Testcontainers Postgres database and the application context starts successfully with `ddl-auto=validate` against the result. This slice adds no JPA entities, so that last check doesn't yet prove Hibernate's mappings agree with the schema — it only proves Flyway applies without error and the context starts on top of the result. The entity-mapping agreement becomes a real check once a later slice introduces entities.

## Failure case / happy-path → test method map

Count: 33 test methods total in this slice (23 failure cases + 7 happy paths + 1 migration test + 1 index-coverage test, all in `SchemaConstraintsTest` except the migration test, which is in `FlywayMigrationTest`), plus `GiveawayTrustEngineApplicationTests.contextLoads` (now self-contained via Testcontainers, no longer dependent on `.env`/compose).

| Case | Test method | Constraint name asserted |
|---|---|---|
| 1 (PRD 17 payment idempotency) | `duplicatePaymentEventRejected` | `uq_payment_event_provider_event_id` |
| 2 (PRD 3/16/17 atomic quota claim) | `quotaOverdrawRejected` | `ck_account_quota_rolls_used_le_allocated` |
| 3 (orphan rows, 5 tables) | `orphanRowsRejected` | `fk_giveaway_entry_giveaway_id`, `fk_giveaway_cm_id`, `fk_account_quota_cm_id`, `fk_refresh_token_cm_id`, `fk_payment_event_cm_id` |
| 4 (invalid enum) | `invalidEnumValueRejected` | `ck_giveaway_status` |
| 5 (PRD 3 failure fields) | `failureFieldsWithoutFailedStatusRejected` | `ck_giveaway_failure_fields_only_when_failed` |
| 6 (duplicate CM email/handle) | `duplicateCommunityManagerEmailOrHandleRejected` | `uq_community_manager_email`, `uq_community_manager_x_handle` |
| 7 (1:1 cm↔quota) | `secondQuotaRowForSameCmRejected` | `uq_account_quota_cm_id` |
| 8 (PRD 10 slug before finalization) | `receiptSlugBeforeFinalizationRejected` | `ck_giveaway_receipt_slug_only_when_finalized` |
| 9 (PRD 10 finalized without slug) | `finalizedGiveawayWithoutSlugRejected` | `ck_giveaway_receipt_slug_only_when_finalized` (same constraint, other direction) |
| 10 (duplicate slug) | `duplicateReceiptSlugRejected` | `uq_giveaway_receipt_slug` |
| 11 (target_winners range) | `targetWinnersOutOfRangeRejected` | `ck_giveaway_target_winners_range` |
| 12 (guaranteed handles cardinality) | `tooManyGuaranteedHandlesRejected` | `ck_giveaway_guaranteed_handles_cardinality` |
| 13 (PRD 17 handle conflict) | `guaranteedExcludedOverlapRejected` | `ck_giveaway_guaranteed_excluded_no_overlap` |
| 14 (eligibility/code drift) | `eligibilityDisqualificationDriftRejected` | `ck_giveaway_entry_eligibility_matches_code` |
| 15 (winner/allocation drift) | `winnerFlagAllocationDriftRejected` | `ck_giveaway_entry_winner_matches_allocation` |
| 16 (ineligible winner) | `ineligibleWinnerRejected` | `ck_giveaway_entry_winner_must_be_eligible` |
| 17 (negative/zero payment amounts) | `negativeOrZeroPaymentAmountsRejected` | `ck_payment_event_amount_cents_nonneg`, `ck_payment_event_rolls_purchased_positive` |
| 18 (invalid payment status) | `invalidPaymentStatusRejected` | `ck_payment_event_status` |
| 19 (cascade delete) | `cascadeDeleteRemovesChildEntries` | n/a (asserts cascade behavior, not a rejection) |
| 20 (finalized_at ↔ status) | `finalizedWithoutFinalizedAtRejected` | `ck_giveaway_finalized_at_matches_status` |
| 21 (PRD 15 guaranteed deadline) | `guaranteedResolutionWithoutDeadlineRejected` | `ck_giveaway_guaranteed_deadline_required` |
| 22 (negative counters) | `negativeCountersRejected` | `ck_giveaway_raw_replies_count_nonneg`, `ck_giveaway_valid_entries_count_nonneg` |
| 23 (duplicate giveaway_id+reply_id) | `duplicateGiveawayReplyIdRejected` | `uq_giveaway_entry_giveaway_id_reply_id` |
| happy path × 7 | `happyPathCommunityManager`, `happyPathAccountQuota`, `happyPathGiveaway`, `happyPathGiveawayEntry`, `happyPathRefreshToken`, `happyPathPaymentEvent`, `happyPathGiveawayLogs` | n/a |
| migration test | `FlywayMigrationTest.flywayAppliesV1CleanlyAndContextStartsWithDdlAutoValidate` | n/a |
| index coverage | `allPlannedIndexesExistWithExpectedColumns` | asserts, via `pg_indexes.indexdef`, that every index named in this plan exists on the right table with the right column order: `idx_giveaway_cm_id_status`, `idx_entry_giveaway_winner`, `idx_entry_giveaway_order`, `idx_entry_giveaway_handle`, `idx_refresh_token_family_id`, `idx_logs_giveaway_id`, `idx_logs_giveaway_id_created_at` |
| app context self-contained | `GiveawayTrustEngineApplicationTests.contextLoads` | n/a — now self-contained via Testcontainers Postgres/Redis (`@DynamicPropertySource`), no `.env`/compose dependency |

Total: 33 test methods (23 failure cases + 7 happy paths + 1 migration test + 1 index-coverage test, all in `SchemaConstraintsTest` except the migration test in `FlywayMigrationTest`), plus `contextLoads`.

Mutation-tested (constraint/index temporarily removed from `V1__initial_schema.sql`, confirmed a clear named-constraint/index failure, then restored): `ck_giveaway_receipt_slug_only_when_finalized`, `ck_giveaway_entry_winner_must_be_eligible`, `ck_giveaway_guaranteed_excluded_no_overlap`, `uq_payment_event_provider_event_id`, `idx_entry_giveaway_handle`.

Testcontainers Postgres image is pinned to `postgres:17-alpine` via a shared `TestImages.POSTGRES` constant (`src/test/java/com/giveaway/giveawaytrustengine/TestImages.java`), matching docker-compose.yaml's `postgres:17` major version.

Every negative test now asserts the specific named constraint via `PSQLException.getServerErrorMessage().getConstraint()`, not only the SQLSTATE class — proving the exact invariant failed, not a coincidentally-matching one of the same kind. V1 (below) names every constraint to match.

## Test infrastructure note

Testcontainers' default Docker API client version is rejected by this environment's Docker daemon (API 1.55 requires client ≥ 1.40, default shaded client reports 1.32). Pinned via `src/test/resources/docker-java.properties` (`api.version=1.44`), which is docker-java's own config-file mechanism — verified working by removing the previous `pom.xml` surefire `systemPropertyVariables` pin entirely and re-running; the properties file alone was sufficient. No pom.xml build-config changes needed for this; it's a pure test-resource file, standard docker-java config, not something future environments running a different Docker daemon would need to touch.

## Logs and metrics

None — this slice ships schema only, no application code paths that emit log lines or metrics. The `giveaway_logs` table itself is created here so slice 2 onward can write to it immediately.
