package com.giveaway.giveawaytrustengine.quota;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

/**
 * Slice 4 (Quota) -- CRITICAL REVIEW. See docs/slices/04-quota.md.
 *
 * <p><b>{@code claimRoll} and {@code refundRoll} are each one conditional {@code UPDATE}</b> --
 * never a read in Java followed by a write (CLAUDE.md: "money and quota math happens in SQL,
 * never read then write in Java") -- so Postgres's own row-level locking is what actually
 * serializes concurrent callers, not application logic. The `account_quota` table's own CHECK
 * constraints ({@code rolls_used >= 0}, {@code rolls_used <= rolls_allocated}) are the backstop
 * if either guard is ever removed by a future regression; they are not meant to fire in normal
 * operation.
 *
 * <p><b>{@code refundRoll}'s guard only prevents a negative value -- it does not, and cannot,
 * detect a double refund.</b> A second refund of an already-refunded claim looks identical, at
 * the database level, to any other legitimate refund. Closing that gap is an explicit
 * requirement on whoever calls this (slice 5): refund exactly once per failed giveaway, in the
 * same transaction as the giveaway's own state change.
 */
public class AccountQuotaService {

    private static final Logger log = LoggerFactory.getLogger(AccountQuotaService.class);

    private static final String FAILURE_COUNTER_NAME = "giveaway.quota.failure";

    private final DataSource dataSource;
    private final MeterRegistry meterRegistry;

    public AccountQuotaService(DataSource dataSource) {
        this(dataSource, new SimpleMeterRegistry());
    }

    public AccountQuotaService(DataSource dataSource, MeterRegistry meterRegistry) {
        this.dataSource = dataSource;
        this.meterRegistry = meterRegistry;
    }

    /**
     * Claims one roll via {@code UPDATE account_quota SET rolls_used = rolls_used + 1 WHERE
     * cm_id = ? AND rolls_used < rolls_allocated}. Returns {@code false} when no roll is left --
     * the caller maps that to HTTP 402 (slice 5). Never throws for a clean "no roll left"
     * rejection; only for a genuine DB failure or a missing {@code account_quota} row.
     */
    public boolean claimRoll(UUID cmId) {
        try (Connection conn = dataSource.getConnection();
                PreparedStatement ps = conn.prepareStatement(
                        "UPDATE account_quota SET rolls_used = rolls_used + 1 "
                                + "WHERE cm_id = ? AND rolls_used < rolls_allocated")) {
            ps.setObject(1, cmId);
            int updated = ps.executeUpdate();
            if (updated == 1) {
                log.info("quota claim: cmId={} outcome=claimed", cmId);
                return true;
            }
            requireAccountQuotaRowExists(conn, cmId);
            log.info("quota claim rejected: cmId={} reason=exhausted", cmId);
            meterRegistry.counter(FAILURE_COUNTER_NAME, "reason", "exhausted").increment();
            return false;
        }
        catch (SQLException e) {
            recordDbFailure();
            throw new IllegalStateException("failed to claim roll", e);
        }
    }

    /**
     * Refunds one roll via {@code UPDATE account_quota SET rolls_used = rolls_used - 1 WHERE
     * cm_id = ? AND rolls_used > 0}. Returns {@code false} on an over-refund (including a double
     * refund of the same claim) -- the guard only stops a negative value, it does not detect or
     * prevent a double refund; see the class Javadoc.
     */
    public boolean refundRoll(UUID cmId) {
        try (Connection conn = dataSource.getConnection();
                PreparedStatement ps = conn.prepareStatement(
                        "UPDATE account_quota SET rolls_used = rolls_used - 1 "
                                + "WHERE cm_id = ? AND rolls_used > 0")) {
            ps.setObject(1, cmId);
            int updated = ps.executeUpdate();
            if (updated == 1) {
                log.info("quota refund: cmId={} outcome=refunded", cmId);
                return true;
            }
            requireAccountQuotaRowExists(conn, cmId);
            return false;
        }
        catch (SQLException e) {
            recordDbFailure();
            throw new IllegalStateException("failed to refund roll", e);
        }
    }

    /**
     * Credits {@code amount} additional rolls via {@code UPDATE account_quota SET
     * rolls_allocated = rolls_allocated + ? WHERE cm_id = ?}. Called by the Bachs webhook
     * (slice 10) on a successful payment event; {@code payment_event}'s own {@code (provider,
     * event_id)} unique constraint (slice 1) is what stops a redelivered webhook from reaching
     * this twice for the same event, not anything in this method.
     *
     * @throws IllegalArgumentException if {@code amount} is zero or negative -- rejected before
     *         any SQL is issued.
     */
    public void addRolls(UUID cmId, int amount) {
        if (amount <= 0) {
            throw new IllegalArgumentException("amount must be positive, got " + amount);
        }
        try (Connection conn = dataSource.getConnection();
                PreparedStatement ps = conn.prepareStatement(
                        "UPDATE account_quota SET rolls_allocated = rolls_allocated + ? WHERE cm_id = ?")) {
            ps.setInt(1, amount);
            ps.setObject(2, cmId);
            int updated = ps.executeUpdate();
            if (updated == 0) {
                // Unlike claimRoll/refundRoll, there is no guard condition to disambiguate from
                // here -- the only WHERE clause is the cmId match itself, so zero rows can only
                // mean one thing.
                throw new IllegalStateException("no account_quota row for cmId=" + cmId);
            }
        }
        catch (SQLException e) {
            recordDbFailure();
            throw new IllegalStateException("failed to add rolls", e);
        }
    }

    /**
     * Disambiguates a zero-rows result from {@code claimRoll}/{@code refundRoll}: did the guard
     * legitimately trip (the row exists, just not in the required state), or does the {@code
     * account_quota} row not exist at all (a data-integrity bug that should structurally never
     * happen, per {@code CommunityManagerRepository}'s 1:1 creation guarantee)? Run only on the
     * zero-rows path -- the happy path never issues this extra query.
     */
    private void requireAccountQuotaRowExists(Connection conn, UUID cmId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement("SELECT 1 FROM account_quota WHERE cm_id = ?")) {
            ps.setObject(1, cmId);
            try (ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    throw new IllegalStateException("no account_quota row for cmId=" + cmId);
                }
            }
        }
    }

    /** Never logs SQL text or any value beyond the fixed reason category. */
    private void recordDbFailure() {
        log.warn("quota operation rejected: reason=db-unavailable");
        meterRegistry.counter(FAILURE_COUNTER_NAME, "reason", "db-unavailable").increment();
    }
}
