package com.giveaway.giveawaytrustengine.schema;

import com.giveaway.giveawaytrustengine.TestImages;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Instant;
import java.util.UUID;

import static com.giveaway.giveawaytrustengine.schema.SchemaTestSupport.*;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * RED step for slice 1 (docs/slices/01-migrations-and-schema.md).
 *
 * These tests run plain JDBC against a real Testcontainers Postgres and prove that every
 * invariant in the plan is enforced by the DATABASE itself (CLAUDE.md: "Invariants live in
 * database constraints ... not only in code"), not by application code that doesn't exist yet.
 *
 * No Flyway migration exists yet and no application code exists yet, so every statement here
 * is expected to fail right now with SQLSTATE 42P01 (relation does not exist) instead of the
 * constraint-specific SQLSTATE asserted (23505 unique_violation / 23503 foreign_key_violation /
 * 23514 check_violation). That mismatch is the expected, desired RED failure for this step:
 * it proves the schema does not exist yet, not that the test itself is broken.
 */
@Testcontainers
class SchemaConstraintsTest {

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(TestImages.POSTGRES)
            .withDatabaseName("giveaway_trust_engine_test")
            .withUsername("test")
            .withPassword("test");

    static Connection conn;

    @BeforeAll
    static void startContainerAndConnect() throws SQLException {
        POSTGRES.start();
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .load()
                .migrate();
        conn = DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        conn.setAutoCommit(true);
    }

    @AfterAll
    static void stopContainerAndDisconnect() throws SQLException {
        if (conn != null) {
            conn.close();
        }
        POSTGRES.stop();
    }

    // ---- Failure case 1: PRD section 17, "Payment idempotency" ------------------------------
    @Test
    @DisplayName("case 1 (PRD 17 Payment idempotency): duplicate (provider, event_id) rejected")
    void duplicatePaymentEventRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);
        insertPaymentEvent(conn, "BACHS", "evt-123", cmId, 1000, 5, "SUCCEEDED");

        assertConstraintViolation("23505", "uq_payment_event_provider_event_id", () ->
                insertPaymentEvent(conn, "BACHS", "evt-123", cmId, 1000, 5, "SUCCEEDED"));
    }

    // ---- Failure case 2: PRD section 3/16/17, "Atomic quota claim" --------------------------
    @Test
    @DisplayName("case 2 (PRD 3/16/17 Atomic quota claim): rolls_used > rolls_allocated rejected")
    void quotaOverdrawRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);

        assertConstraintViolation("23514", "ck_account_quota_rolls_used_le_allocated", () ->
                insertAccountQuota(conn, cmId, 5, 6));
    }

    // ---- Failure case 3: orphan rows across the five tables with FKs on cm_id/giveaway_id -----
    @Test
    @DisplayName("case 3: orphan rows with a non-existent parent id rejected on every FK table")
    void orphanRowsRejected() {
        UUID nonExistentCmId = UUID.randomUUID();
        UUID nonExistentGiveawayId = UUID.randomUUID();

        assertConstraintViolation("23503", "fk_giveaway_entry_giveaway_id", () -> {
            GiveawayEntryRow row = new GiveawayEntryRow().giveawayId(nonExistentGiveawayId);
            insertGiveawayEntry(conn, row);
        });

        assertConstraintViolation("23503", "fk_giveaway_cm_id", () -> {
            GiveawayRow row = new GiveawayRow().cmId(nonExistentCmId);
            insertGiveaway(conn, row);
        });

        assertConstraintViolation("23503", "fk_account_quota_cm_id", () ->
                insertAccountQuota(conn, nonExistentCmId, 10, 0));

        assertConstraintViolation("23503", "fk_refresh_token_cm_id", () ->
                insertRefreshToken(conn, nonExistentCmId, UUID.randomUUID(), false,
                        FIXED_NOW.plusSeconds(900)));

        assertConstraintViolation("23503", "fk_payment_event_cm_id", () ->
                insertPaymentEvent(conn, "BACHS", "evt-orphan", nonExistentCmId, 1000, 5, "SUCCEEDED"));
    }

    // ---- Failure case 4: PRD section 3, enums stored as text + check -----------------------
    @Test
    @DisplayName("case 4: invalid enum value (giveaway.status = 'BOGUS') rejected")
    void invalidEnumValueRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);

        assertConstraintViolation("23514", "ck_giveaway_status", () -> {
            GiveawayRow row = new GiveawayRow().cmId(cmId);
            row.status = "BOGUS";
            insertGiveaway(conn, row);
        });
    }

    // ---- Failure case 5: PRD section 3, "only ever populated when status = FAILED" ---------
    @Test
    @DisplayName("case 5 (PRD 3): failure_reason set without status = FAILED rejected")
    void failureFieldsWithoutFailedStatusRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);

        assertConstraintViolation("23514", "ck_giveaway_failure_fields_only_when_failed", () -> {
            GiveawayRow row = new GiveawayRow().cmId(cmId);
            row.status = "PENDING_SCRAPE";
            row.failureReason = "POST_DELETED";
            insertGiveaway(conn, row);
        });
    }

    // ---- Failure case 6: unique community_manager email / x_user_id ------------------------
    @Test
    @DisplayName("case 6: duplicate community_manager email and x_user_id each rejected")
    void duplicateCommunityManagerEmailOrXUserIdRejected() throws SQLException {
        String sharedEmail = "dup-" + UUID.randomUUID() + "@example.com";
        String firstHandle = "@cm_" + UUID.randomUUID().toString().substring(0, 8);
        insertCommunityManager(conn, sharedEmail, firstHandle);

        assertConstraintViolation("23505", "uq_community_manager_email", () ->
                insertCommunityManager(conn, sharedEmail, "@cm_" + UUID.randomUUID().toString().substring(0, 8)));

        String sharedXUserId = "x-user-" + UUID.randomUUID();
        insertCommunityManager(conn, "owner-" + UUID.randomUUID() + "@example.com",
                "@cm_" + UUID.randomUUID().toString().substring(0, 8), sharedXUserId);

        assertConstraintViolation("23505", "uq_community_manager_x_user_id", () ->
                insertCommunityManager(conn, "other-" + UUID.randomUUID() + "@example.com",
                        "@cm_" + UUID.randomUUID().toString().substring(0, 8), sharedXUserId));
    }

    // ---- Failure case 6a (V3 migration): x_handle is explicitly NOT unique anymore ----------
    // V1 made x_handle UNIQUE; V2 added x_user_id as the real, immutable identity key (X allows
    // handle changes); V3 (chunk 4 fix) drops x_handle's own UNIQUE constraint because it is no
    // longer an identity column -- this slice's own OAuth upsert (INSERT ... ON CONFLICT
    // (x_user_id) DO UPDATE SET x_handle = ...) refreshes it on every login, and a second,
    // redundant UNIQUE constraint on that same refreshed value broke the upsert under a race
    // (OAuthLoginFlowTest#concurrentFirstTimeLoginsForSameXUserCreateExactlyOneRow). Two
    // different x_user_ids sharing the same x_handle value must now succeed at the DB level.
    @Test
    @DisplayName("case 6a (V3): x_handle is no longer unique -- two different x_user_ids may share one")
    void xHandleIsNoLongerUnique() throws SQLException {
        String sharedHandle = "@cm_" + UUID.randomUUID().toString().substring(0, 8);
        insertCommunityManager(conn, "owner-" + UUID.randomUUID() + "@example.com", sharedHandle);

        UUID secondId = insertCommunityManager(
                conn, "other-" + UUID.randomUUID() + "@example.com", sharedHandle);
        assertNotNull(secondId);
    }

    // ---- Failure case 7: Section 3, 1:1 cm <-> account_quota --------------------------------
    @Test
    @DisplayName("case 7 (PRD 3): second account_quota row for the same cm_id rejected")
    void secondQuotaRowForSameCmRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);
        insertAccountQuota(conn, cmId, 10, 0);

        assertConstraintViolation("23505", "uq_account_quota_cm_id", () ->
                insertAccountQuota(conn, cmId, 10, 0));
    }

    // ---- Failure case 8: PRD section 10, slug only exists after finalization ---------------
    @Test
    @DisplayName("case 8 (PRD 10): receipt_slug set before finalization rejected")
    void receiptSlugBeforeFinalizationRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);

        assertConstraintViolation("23514", "ck_giveaway_receipt_slug_only_when_finalized", () -> {
            GiveawayRow row = new GiveawayRow().cmId(cmId);
            row.status = "PROCESSING";
            row.receiptSlug = "some-slug";
            insertGiveaway(conn, row);
        });
    }

    // ---- Failure case 9: PRD section 10, finalized giveaway must carry a slug --------------
    @Test
    @DisplayName("case 9 (PRD 10): finalizing a giveaway with no receipt_slug rejected")
    void finalizedGiveawayWithoutSlugRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);
        GiveawayRow row = new GiveawayRow().cmId(cmId);
        row.status = "PROCESSING";
        UUID giveawayId = insertGiveaway(conn, row);

        assertConstraintViolation("23514", "ck_giveaway_receipt_slug_only_when_finalized", () ->
                updateGiveawayStatusAndFields(conn, giveawayId, "FINALIZED", null, FIXED_NOW, null));
    }

    // ---- Failure case 10: unique receipt_slug ----------------------------------------------
    @Test
    @DisplayName("case 10: duplicate receipt_slug across giveaways rejected")
    void duplicateReceiptSlugRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);
        String slug = "slug-" + UUID.randomUUID();

        GiveawayRow first = new GiveawayRow().cmId(cmId);
        first.status = "FINALIZED";
        first.receiptSlug = slug;
        first.finalizedAt = FIXED_NOW;
        insertGiveaway(conn, first);

        assertConstraintViolation("23505", "uq_giveaway_receipt_slug", () -> {
            GiveawayRow second = new GiveawayRow().cmId(cmId);
            second.status = "FINALIZED";
            second.receiptSlug = slug;
            second.finalizedAt = FIXED_NOW;
            insertGiveaway(conn, second);
        });
    }

    // ---- Failure case 11: target_winners between 1 and 100 ---------------------------------
    @Test
    @DisplayName("case 11: target_winners = 0 and target_winners = 101 each rejected")
    void targetWinnersOutOfRangeRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);

        assertConstraintViolation("23514", "ck_giveaway_target_winners_range", () -> {
            GiveawayRow row = new GiveawayRow().cmId(cmId);
            row.targetWinners = 0;
            insertGiveaway(conn, row);
        });

        assertConstraintViolation("23514", "ck_giveaway_target_winners_range", () -> {
            GiveawayRow row = new GiveawayRow().cmId(cmId);
            row.targetWinners = 101;
            insertGiveaway(conn, row);
        });
    }

    // ---- Failure case 12: cardinality(guaranteed_handles) <= target_winners ----------------
    @Test
    @DisplayName("case 12: more guaranteed_handles than target_winners rejected")
    void tooManyGuaranteedHandlesRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);

        assertConstraintViolation("23514", "ck_giveaway_guaranteed_handles_cardinality", () -> {
            GiveawayRow row = new GiveawayRow().cmId(cmId);
            row.targetWinners = 1;
            row.guaranteedHandles = new String[] {"@alice", "@bob"};
            insertGiveaway(conn, row);
        });
    }

    // ---- Failure case 13: PRD 17, "Input validation, handle conflict" at schema level ------
    @Test
    @DisplayName("case 13 (PRD 17 handle conflict): overlapping guaranteed/excluded handles rejected")
    void guaranteedExcludedOverlapRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);

        assertConstraintViolation("23514", "ck_giveaway_guaranteed_excluded_no_overlap", () -> {
            GiveawayRow row = new GiveawayRow().cmId(cmId);
            row.targetWinners = 5;
            row.guaranteedHandles = new String[] {"@alice"};
            row.excludedHandles = new String[] {"@alice"};
            insertGiveaway(conn, row);
        });
    }

    // ---- Failure case 14: giveaway_entry eligibility / disqualification_code drift ---------
    @Test
    @DisplayName("case 14: eligible entry with a disqualification_code, and ineligible entry with none, both rejected")
    void eligibilityDisqualificationDriftRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);
        UUID giveawayId = insertGiveaway(conn, new GiveawayRow().cmId(cmId));

        assertConstraintViolation("23514", "ck_giveaway_entry_eligibility_matches_code", () -> {
            GiveawayEntryRow row = new GiveawayEntryRow().giveawayId(giveawayId);
            row.isEligible = true;
            row.disqualificationCode = "WRONG_CHAIN";
            insertGiveawayEntry(conn, row);
        });

        assertConstraintViolation("23514", "ck_giveaway_entry_eligibility_matches_code", () -> {
            GiveawayEntryRow row = new GiveawayEntryRow().giveawayId(giveawayId);
            row.isEligible = false;
            row.disqualificationCode = null;
            insertGiveawayEntry(conn, row);
        });
    }

    // ---- Failure case 15: giveaway_entry winner flag / winner_allocation drift -------------
    @Test
    @DisplayName("case 15: winner flag and winner_allocation disagreeing, in either direction, rejected")
    void winnerFlagAllocationDriftRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);
        UUID giveawayId = insertGiveaway(conn, new GiveawayRow().cmId(cmId));

        assertConstraintViolation("23514", "ck_giveaway_entry_winner_matches_allocation", () -> {
            GiveawayEntryRow row = new GiveawayEntryRow().giveawayId(giveawayId);
            row.isWinner = true;
            row.winnerAllocation = null;
            insertGiveawayEntry(conn, row);
        });

        assertConstraintViolation("23514", "ck_giveaway_entry_winner_matches_allocation", () -> {
            GiveawayEntryRow row = new GiveawayEntryRow().giveawayId(giveawayId);
            row.isWinner = false;
            row.winnerAllocation = "RANDOM_SELECTION";
            insertGiveawayEntry(conn, row);
        });
    }

    // ---- Failure case 16: a winner must be eligible ----------------------------------------
    @Test
    @DisplayName("case 16: an ineligible winner (is_winner = true, is_eligible = false) rejected")
    void ineligibleWinnerRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);
        UUID giveawayId = insertGiveaway(conn, new GiveawayRow().cmId(cmId));

        assertConstraintViolation("23514", "ck_giveaway_entry_winner_must_be_eligible", () -> {
            GiveawayEntryRow row = new GiveawayEntryRow().giveawayId(giveawayId);
            row.isWinner = true;
            row.winnerAllocation = "RANDOM_SELECTION";
            row.isEligible = false;
            row.disqualificationCode = "WRONG_CHAIN";
            insertGiveawayEntry(conn, row);
        });
    }

    // ---- Failure case 17: payment_event amount/rolls must be positive ----------------------
    @Test
    @DisplayName("case 17: negative amount_cents and zero rolls_purchased each rejected")
    void negativeOrZeroPaymentAmountsRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);

        assertConstraintViolation("23514", "ck_payment_event_amount_cents_nonneg", () ->
                insertPaymentEvent(conn, "BACHS", "evt-neg-amount", cmId, -1, 5, "SUCCEEDED"));

        assertConstraintViolation("23514", "ck_payment_event_rolls_purchased_positive", () ->
                insertPaymentEvent(conn, "BACHS", "evt-zero-rolls", cmId, 1000, 0, "SUCCEEDED"));
    }

    // ---- Failure case 18: payment_event.status enum check ----------------------------------
    @Test
    @DisplayName("case 18: invalid payment_event.status rejected")
    void invalidPaymentStatusRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);

        assertConstraintViolation("23514", "ck_payment_event_status", () ->
                insertPaymentEvent(conn, "BACHS", "evt-bogus-status", cmId, 1000, 5, "BOGUS"));
    }

    // ---- Failure case 19: ON DELETE CASCADE from giveaway to giveaway_entry ----------------
    @Test
    @DisplayName("case 19: deleting a giveaway cascades to delete its entries")
    void cascadeDeleteRemovesChildEntries() throws SQLException {
        UUID cmId = insertCommunityManager(conn);
        UUID giveawayId = insertGiveaway(conn, new GiveawayRow().cmId(cmId));
        insertGiveawayEntry(conn, new GiveawayEntryRow().giveawayId(giveawayId));
        insertGiveawayEntry(conn, new GiveawayEntryRow().giveawayId(giveawayId));

        assertEquals(2, countRows(conn,
                "SELECT count(*) FROM giveaway_entry WHERE giveaway_id = '" + giveawayId + "'"));

        try (var ps = conn.prepareStatement("DELETE FROM giveaway WHERE id = ?")) {
            ps.setObject(1, giveawayId);
            ps.executeUpdate();
        }

        assertEquals(0, countRows(conn,
                "SELECT count(*) FROM giveaway_entry WHERE giveaway_id = '" + giveawayId + "'"),
                "deleting the parent giveaway should cascade to its entries, not orphan or reject them");
    }

    // ---- Failure case 20: (status = FINALIZED) <=> (finalized_at IS NOT NULL) --------------
    @Test
    @DisplayName("case 20: finalized status without finalized_at, and the inverse, both rejected")
    void finalizedWithoutFinalizedAtRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);

        assertConstraintViolation("23514", "ck_giveaway_finalized_at_matches_status", () -> {
            GiveawayRow row = new GiveawayRow().cmId(cmId);
            row.status = "FINALIZED";
            row.receiptSlug = "slug-" + UUID.randomUUID();
            row.finalizedAt = null;
            insertGiveaway(conn, row);
        });

        assertConstraintViolation("23514", "ck_giveaway_finalized_at_matches_status", () -> {
            GiveawayRow row = new GiveawayRow().cmId(cmId);
            row.status = "PROCESSING";
            row.finalizedAt = FIXED_NOW;
            insertGiveaway(conn, row);
        });
    }

    // ---- Failure case 21: PRD section 15, deadline stored when entering guaranteed resolution
    @Test
    @DisplayName("case 21 (PRD 15): AWAITING_GUARANTEED_RESOLUTION without guaranteed_deadline rejected")
    void guaranteedResolutionWithoutDeadlineRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);

        assertConstraintViolation("23514", "ck_giveaway_guaranteed_deadline_required", () -> {
            GiveawayRow row = new GiveawayRow().cmId(cmId);
            row.status = "AWAITING_GUARANTEED_RESOLUTION";
            row.guaranteedDeadline = null;
            insertGiveaway(conn, row);
        });
    }

    // ---- Failure case 22: counters can never go negative -----------------------------------
    @Test
    @DisplayName("case 22: negative raw_replies_count and negative valid_entries_count each rejected")
    void negativeCountersRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);

        assertConstraintViolation("23514", "ck_giveaway_raw_replies_count_nonneg", () -> {
            GiveawayRow row = new GiveawayRow().cmId(cmId);
            row.rawRepliesCount = -1;
            insertGiveaway(conn, row);
        });

        assertConstraintViolation("23514", "ck_giveaway_valid_entries_count_nonneg", () -> {
            GiveawayRow row = new GiveawayRow().cmId(cmId);
            row.validEntriesCount = -1;
            insertGiveaway(conn, row);
        });
    }

    // ---- Failure case 23: slice 6 dedup note, unique(giveaway_id, reply_id) ----------------
    @Test
    @DisplayName("case 23: duplicate (giveaway_id, reply_id) rejected")
    void duplicateGiveawayReplyIdRejected() throws SQLException {
        UUID cmId = insertCommunityManager(conn);
        UUID giveawayId = insertGiveaway(conn, new GiveawayRow().cmId(cmId));
        long replyId = 42L;

        GiveawayEntryRow first = new GiveawayEntryRow().giveawayId(giveawayId);
        first.replyId = replyId;
        insertGiveawayEntry(conn, first);

        assertConstraintViolation("23505", "uq_giveaway_entry_giveaway_id_reply_id", () -> {
            GiveawayEntryRow second = new GiveawayEntryRow().giveawayId(giveawayId);
            second.replyId = replyId;
            insertGiveawayEntry(conn, second);
        });
    }

    // ---- Happy path: one minimal valid row per table (all seven) ---------------------------

    @Test
    @DisplayName("happy path: community_manager minimal valid row inserts")
    void happyPathCommunityManager() throws SQLException {
        UUID id = insertCommunityManager(conn);
        assertEquals(1, countRows(conn, "SELECT count(*) FROM community_manager WHERE id = '" + id + "'"));
    }

    @Test
    @DisplayName("happy path: account_quota minimal valid row inserts")
    void happyPathAccountQuota() throws SQLException {
        UUID cmId = insertCommunityManager(conn);
        UUID id = insertAccountQuota(conn, cmId, 10, 0);
        assertEquals(1, countRows(conn, "SELECT count(*) FROM account_quota WHERE id = '" + id + "'"));
    }

    @Test
    @DisplayName("happy path: giveaway minimal valid row inserts")
    void happyPathGiveaway() throws SQLException {
        UUID cmId = insertCommunityManager(conn);
        UUID id = insertGiveaway(conn, new GiveawayRow().cmId(cmId));
        assertEquals(1, countRows(conn, "SELECT count(*) FROM giveaway WHERE id = '" + id + "'"));
    }

    @Test
    @DisplayName("happy path: giveaway_entry minimal valid row inserts")
    void happyPathGiveawayEntry() throws SQLException {
        UUID cmId = insertCommunityManager(conn);
        UUID giveawayId = insertGiveaway(conn, new GiveawayRow().cmId(cmId));
        long entryId = insertGiveawayEntry(conn, new GiveawayEntryRow().giveawayId(giveawayId));
        assertEquals(1, countRows(conn, "SELECT count(*) FROM giveaway_entry WHERE id = " + entryId));
    }

    @Test
    @DisplayName("happy path: refresh_token minimal valid row inserts")
    void happyPathRefreshToken() throws SQLException {
        UUID cmId = insertCommunityManager(conn);
        UUID tokenId = insertRefreshToken(conn, cmId, UUID.randomUUID(), false, FIXED_NOW.plusSeconds(900));
        assertEquals(1, countRows(conn, "SELECT count(*) FROM refresh_token WHERE token_id = '" + tokenId + "'"));
    }

    @Test
    @DisplayName("happy path: payment_event minimal valid row inserts")
    void happyPathPaymentEvent() throws SQLException {
        UUID cmId = insertCommunityManager(conn);
        UUID id = insertPaymentEvent(conn, "BACHS", "evt-happy-" + UUID.randomUUID(), cmId, 1000, 5, "SUCCEEDED");
        assertEquals(1, countRows(conn, "SELECT count(*) FROM payment_event WHERE id = '" + id + "'"));
    }

    @Test
    @DisplayName("happy path: giveaway_logs minimal valid row inserts")
    void happyPathGiveawayLogs() throws SQLException {
        UUID cmId = insertCommunityManager(conn);
        UUID giveawayId = insertGiveaway(conn, new GiveawayRow().cmId(cmId));
        long logId = insertGiveawayLog(conn, giveawayId, "req-" + UUID.randomUUID(), "GIVEAWAY_CREATED");
        assertEquals(1, countRows(conn, "SELECT count(*) FROM giveaway_logs WHERE id = " + logId));
    }

    // ---- Every index named in the plan exists with the right columns, in order --------------
    @Test
    @DisplayName("every index named in the plan exists on the right table with the right column order")
    void allPlannedIndexesExistWithExpectedColumns() throws SQLException {
        assertIndexColumns("idx_giveaway_cm_id_status", "cm_id", "status");
        assertIndexColumns("idx_entry_giveaway_winner", "giveaway_id", "is_winner");
        assertIndexColumns("idx_entry_giveaway_order", "giveaway_id", "reply_timestamp", "reply_id");
        assertIndexColumns("idx_entry_giveaway_handle", "giveaway_id", "author_handle");
        assertIndexColumns("idx_refresh_token_family_id", "family_id");
        assertIndexColumns("idx_logs_giveaway_id", "giveaway_id");
        assertIndexColumns("idx_logs_giveaway_id_created_at", "giveaway_id", "created_at");
    }

    /**
     * Reads pg_indexes.indexdef (e.g. "CREATE INDEX idx_x ON public.t USING btree (a, b)")
     * and asserts the index exists with exactly the given columns, in the given order.
     */
    private static void assertIndexColumns(String indexName, String... expectedColumns) throws SQLException {
        String indexDef;
        try (var ps = conn.prepareStatement(
                "SELECT indexdef FROM pg_indexes WHERE indexname = ?")) {
            ps.setString(1, indexName);
            try (var rs = ps.executeQuery()) {
                if (!rs.next()) {
                    fail("expected index '" + indexName + "' to exist, but pg_indexes has no row for it");
                    return;
                }
                indexDef = rs.getString("indexdef");
            }
        }
        int openParen = indexDef.lastIndexOf('(');
        int closeParen = indexDef.lastIndexOf(')');
        String[] actualColumns = indexDef.substring(openParen + 1, closeParen).split(",\\s*");
        assertArrayEquals(expectedColumns, actualColumns,
                "expected index '" + indexName + "' to have columns " + java.util.Arrays.toString(expectedColumns)
                        + " in that order, but pg_indexes reported: " + indexDef);
    }
}
