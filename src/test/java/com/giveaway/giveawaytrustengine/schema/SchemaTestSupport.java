package com.giveaway.giveawaytrustengine.schema;

import org.junit.jupiter.api.function.Executable;
import org.postgresql.util.PGobject;
import org.postgresql.util.PSQLException;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Shared JDBC helpers for slice 1 schema tests (docs/slices/01-migrations-and-schema.md).
 * Every helper writes a row that is otherwise valid against every OTHER constraint in the
 * plan, so a single helper call can be used to isolate exactly one constraint violation
 * at a time without tripping unrelated checks.
 */
final class SchemaTestSupport {

    /** Fixed instant so every test is deterministic; no test calls Instant.now() directly. */
    static final Instant FIXED_NOW = Instant.parse("2026-10-20T12:00:00Z");

    private SchemaTestSupport() {
    }

    /**
     * Runs {@code action} and asserts it fails with the given Postgres SQLSTATE
     * (e.g. 23505 unique_violation, 23503 foreign_key_violation, 23514 check_violation)
     * AND that the specific named constraint in {@code expectedConstraintName} is the one
     * that was violated -- not merely that some constraint of that class failed. This proves
     * the exact invariant from the plan is enforced, not a coincidentally-matching one.
     * This is the DB-level assertion CLAUDE.md requires ("invariants live in database
     * constraints") rather than trusting application code.
     */
    static void assertConstraintViolation(String expectedSqlState, String expectedConstraintName,
                                           Executable action) {
        SQLException ex = assertThrows(SQLException.class, action,
                "expected a SQLSTATE " + expectedSqlState + " violation of constraint '"
                        + expectedConstraintName + "', but no exception was thrown at all");
        assertEquals(expectedSqlState, ex.getSQLState(),
                "expected SQLSTATE " + expectedSqlState + " but got " + ex.getSQLState()
                        + " (" + ex.getMessage() + ")");
        String actualConstraintName = constraintNameOf(ex);
        assertEquals(expectedConstraintName, actualConstraintName,
                "expected constraint '" + expectedConstraintName + "' to be violated but the "
                        + "database reported '" + actualConstraintName + "' (" + ex.getMessage()
                        + ") -- an operator reading the Postgres log would see this exact "
                        + "constraint name for the rejected statement");
    }

    private static String constraintNameOf(SQLException ex) {
        if (ex instanceof PSQLException pe && pe.getServerErrorMessage() != null) {
            return pe.getServerErrorMessage().getConstraint();
        }
        return null;
    }

    static UUID insertCommunityManager(Connection conn, String email, String handle) throws SQLException {
        UUID id = UUID.randomUUID();
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO community_manager (id, email, x_handle, created_at) VALUES (?,?,?,?)")) {
            ps.setObject(1, id);
            ps.setString(2, email);
            ps.setString(3, handle);
            ps.setTimestamp(4, Timestamp.from(FIXED_NOW));
            ps.executeUpdate();
        }
        return id;
    }

    static UUID insertCommunityManager(Connection conn) throws SQLException {
        String unique = UUID.randomUUID().toString();
        return insertCommunityManager(conn, unique + "@example.com", "@cm_" + unique.substring(0, 8));
    }

    static UUID insertAccountQuota(Connection conn, UUID cmId, int rollsAllocated, int rollsUsed) throws SQLException {
        UUID id = UUID.randomUUID();
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO account_quota (id, cm_id, rolls_allocated, rolls_used) VALUES (?,?,?,?)")) {
            ps.setObject(1, id);
            ps.setObject(2, cmId);
            ps.setInt(3, rollsAllocated);
            ps.setInt(4, rollsUsed);
            ps.executeUpdate();
        }
        return id;
    }

    /** Builder-style fixture for the wide `giveaway` table; every column has a valid default. */
    static final class GiveawayRow {
        UUID id = UUID.randomUUID();
        UUID cmId;
        String receiptSlug = null;
        String tweetId = "tweet-" + UUID.randomUUID();
        String chain = "EVM";
        String selectionMode = "RANDOM";
        int targetWinners = 5;
        String status = "PENDING_SCRAPE";
        boolean includeRetweets = false;
        String[] requiredFollowHandles = new String[0];
        String[] excludedHandles = new String[0];
        String[] guaranteedHandles = new String[0];
        int rawRepliesCount = 0;
        int validEntriesCount = 0;
        String failureReason = null;
        String failedStage = null;
        Instant guaranteedDeadline = null;
        Instant finalizedAt = null;
        Instant createdAt = FIXED_NOW;

        GiveawayRow cmId(UUID cmId) {
            this.cmId = cmId;
            return this;
        }
    }

    static UUID insertGiveaway(Connection conn, GiveawayRow row) throws SQLException {
        String sql = "INSERT INTO giveaway (id, cm_id, receipt_slug, tweet_id, chain, selection_mode, "
                + "target_winners, status, include_retweets, required_follow_handles, excluded_handles, "
                + "guaranteed_handles, raw_replies_count, valid_entries_count, failure_reason, failed_stage, "
                + "guaranteed_deadline, finalized_at, created_at) "
                + "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setObject(1, row.id);
            ps.setObject(2, row.cmId);
            ps.setString(3, row.receiptSlug);
            ps.setString(4, row.tweetId);
            ps.setString(5, row.chain);
            ps.setString(6, row.selectionMode);
            ps.setInt(7, row.targetWinners);
            ps.setString(8, row.status);
            ps.setBoolean(9, row.includeRetweets);
            ps.setArray(10, conn.createArrayOf("text", row.requiredFollowHandles));
            ps.setArray(11, conn.createArrayOf("text", row.excludedHandles));
            ps.setArray(12, conn.createArrayOf("text", row.guaranteedHandles));
            ps.setInt(13, row.rawRepliesCount);
            ps.setInt(14, row.validEntriesCount);
            ps.setString(15, row.failureReason);
            ps.setString(16, row.failedStage);
            ps.setTimestamp(17, row.guaranteedDeadline == null ? null : Timestamp.from(row.guaranteedDeadline));
            ps.setTimestamp(18, row.finalizedAt == null ? null : Timestamp.from(row.finalizedAt));
            ps.setTimestamp(19, Timestamp.from(row.createdAt));
            ps.executeUpdate();
        }
        return row.id;
    }

    static void updateGiveawayStatusAndFields(Connection conn, UUID giveawayId, String status,
                                               String receiptSlug, Instant finalizedAt,
                                               Instant guaranteedDeadline) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "UPDATE giveaway SET status = ?, receipt_slug = ?, finalized_at = ?, guaranteed_deadline = ? "
                        + "WHERE id = ?")) {
            ps.setString(1, status);
            ps.setString(2, receiptSlug);
            ps.setTimestamp(3, finalizedAt == null ? null : Timestamp.from(finalizedAt));
            ps.setTimestamp(4, guaranteedDeadline == null ? null : Timestamp.from(guaranteedDeadline));
            ps.setObject(5, giveawayId);
            ps.executeUpdate();
        }
    }

    static final class GiveawayEntryRow {
        UUID giveawayId;
        String authorHandle = "@entrant_" + UUID.randomUUID().toString().substring(0, 8);
        String rawText = "gm wallet: 0xABC";
        String extractedWallet = null;
        Instant replyTimestamp = FIXED_NOW;
        long replyId = Math.abs(UUID.randomUUID().getLeastSignificantBits());
        boolean isEligible = true;
        String disqualificationCode = null;
        boolean isWinner = false;
        String winnerAllocation = null;

        GiveawayEntryRow giveawayId(UUID giveawayId) {
            this.giveawayId = giveawayId;
            return this;
        }
    }

    static long insertGiveawayEntry(Connection conn, GiveawayEntryRow row) throws SQLException {
        String sql = "INSERT INTO giveaway_entry (giveaway_id, author_handle, raw_text, extracted_wallet, "
                + "reply_timestamp, reply_id, is_eligible, disqualification_code, is_winner, winner_allocation) "
                + "VALUES (?,?,?,?,?,?,?,?,?,?) RETURNING id";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setObject(1, row.giveawayId);
            ps.setString(2, row.authorHandle);
            ps.setString(3, row.rawText);
            ps.setString(4, row.extractedWallet);
            ps.setTimestamp(5, Timestamp.from(row.replyTimestamp));
            ps.setLong(6, row.replyId);
            ps.setBoolean(7, row.isEligible);
            ps.setString(8, row.disqualificationCode);
            ps.setBoolean(9, row.isWinner);
            ps.setString(10, row.winnerAllocation);
            var rs = ps.executeQuery();
            rs.next();
            return rs.getLong(1);
        }
    }

    static UUID insertRefreshToken(Connection conn, UUID cmId, UUID familyId, boolean used, Instant expiresAt)
            throws SQLException {
        UUID tokenId = UUID.randomUUID();
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO refresh_token (token_id, family_id, cm_id, used, expires_at) VALUES (?,?,?,?,?)")) {
            ps.setObject(1, tokenId);
            ps.setObject(2, familyId);
            ps.setObject(3, cmId);
            ps.setBoolean(4, used);
            ps.setTimestamp(5, Timestamp.from(expiresAt));
            ps.executeUpdate();
        }
        return tokenId;
    }

    static UUID insertPaymentEvent(Connection conn, String provider, String eventId, UUID cmId,
                                    int amountCents, int rollsPurchased, String status) throws SQLException {
        UUID id = UUID.randomUUID();
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO payment_event (id, provider, event_id, cm_id, amount_cents, rolls_purchased, "
                        + "status, provider_reference, created_at) VALUES (?,?,?,?,?,?,?,?,?)")) {
            ps.setObject(1, id);
            ps.setString(2, provider);
            ps.setString(3, eventId);
            ps.setObject(4, cmId);
            ps.setInt(5, amountCents);
            ps.setInt(6, rollsPurchased);
            ps.setString(7, status);
            ps.setString(8, null);
            ps.setTimestamp(9, Timestamp.from(FIXED_NOW));
            ps.executeUpdate();
        }
        return id;
    }

    static long insertGiveawayLog(Connection conn, UUID giveawayId, String requestId, String eventType)
            throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO giveaway_logs (giveaway_id, request_id, event_type, detail, created_at) "
                        + "VALUES (?,?,?,?,?) RETURNING id")) {
            ps.setObject(1, giveawayId);
            ps.setString(2, requestId);
            ps.setString(3, eventType);
            PGobject detail = new PGobject();
            detail.setType("jsonb");
            detail.setValue("{}");
            ps.setObject(4, detail);
            ps.setTimestamp(5, Timestamp.from(FIXED_NOW));
            var rs = ps.executeQuery();
            rs.next();
            return rs.getLong(1);
        }
    }

    static int countRows(Connection conn, String sql) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(sql); var rs = ps.executeQuery()) {
            if (!rs.next()) {
                fail("expected a count row from: " + sql);
            }
            return rs.getInt(1);
        }
    }
}
