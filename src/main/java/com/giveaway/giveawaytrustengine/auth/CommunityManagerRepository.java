package com.giveaway.giveawaytrustengine.auth;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.util.UUID;

/**
 * Finds or creates the {@code community_manager} row for an X login. See
 * docs/slices/03-auth.md, Section 0.
 *
 * <p><b>A single {@code INSERT ... ON CONFLICT (x_user_id) DO UPDATE ... RETURNING id}</b> --
 * never a select-then-insert -- so two concurrent first-time logins for the same
 * {@code x_user_id} are guaranteed to produce exactly one row: Postgres resolves the unique-index
 * conflict itself, serializing the loser behind the winner's row lock until the winner commits,
 * so the loser's own statement sees and updates the winner's already-committed row rather than
 * racing it. {@code x_handle} is refreshed on every login (a CM can rename their X handle);
 * {@code x_user_id} -- X's immutable numeric id -- is the only identity key, never re-derived
 * from the mutable handle.
 *
 * <p>Whether this call actually inserted a new row is read back from the statement itself (the
 * returned {@code id} equals the candidate id generated before the call only when this call won
 * the insert), not re-derived with a separate existence check that could itself race.
 *
 * <p><b>AccountQuota.</b> The domain model (PRD Section 3) specifies "CommunityManager 1 owns 1
 * AccountQuota" as a mandatory one-to-one relationship, and {@code account_quota.cm_id} carries
 * its own {@code UNIQUE} + {@code FOREIGN KEY} constraint enforcing exactly that. Per this slice's
 * instruction: a brand-new CM gets its {@code account_quota} row created in the SAME transaction
 * as the {@code community_manager} insert -- never a separate transaction that could leave a CM
 * row with no quota row if the process died in between. <b>The PRD does not state a starting
 * {@code rollsAllocated} value for a new signup</b> -- Section 3 only defines the claim/refund/add
 * mechanics once a quota exists, never an initial grant amount. Flagging this rather than
 * guessing a business-meaningful number: this class starts every new CM at
 * {@code rollsAllocated = 0, rollsUsed = 0} (the schema's own {@code CHECK} constraints are
 * satisfied, and a CM who hasn't paid yet correctly gets 402 on any roll attempt) -- confirm
 * before this reaches production if a free signup bonus is actually intended.
 */
public class CommunityManagerRepository {

    private final DataSource dataSource;
    private final Clock clock;

    public CommunityManagerRepository(DataSource dataSource, Clock clock) {
        this.dataSource = dataSource;
        this.clock = clock;
    }

    public record UpsertResult(UUID cmId, boolean isNew) {
    }

    public UpsertResult upsertByXUserId(String xUserId, String xHandle) {
        UUID candidateId = UUID.randomUUID();
        try (Connection conn = dataSource.getConnection()) {
            conn.setAutoCommit(false);
            try {
                UUID resultId = upsertCommunityManager(conn, candidateId, xUserId, xHandle);
                boolean isNew = resultId.equals(candidateId);
                if (isNew) {
                    insertAccountQuota(conn, resultId);
                }
                conn.commit();
                return new UpsertResult(resultId, isNew);
            }
            catch (SQLException e) {
                conn.rollback();
                throw new IllegalStateException("failed to upsert community manager", e);
            }
        }
        catch (SQLException e) {
            throw new IllegalStateException("failed to upsert community manager", e);
        }
    }

    private UUID upsertCommunityManager(Connection conn, UUID candidateId, String xUserId, String xHandle)
            throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO community_manager (id, x_handle, created_at, x_user_id) VALUES (?, ?, ?, ?) "
                        + "ON CONFLICT (x_user_id) DO UPDATE SET x_handle = EXCLUDED.x_handle "
                        + "RETURNING id")) {
            ps.setObject(1, candidateId);
            ps.setString(2, xHandle);
            ps.setTimestamp(3, Timestamp.from(clock.instant()));
            ps.setString(4, xUserId);
            try (ResultSet rs = ps.executeQuery()) {
                rs.next();
                return (UUID) rs.getObject("id");
            }
        }
    }

    private void insertAccountQuota(Connection conn, UUID cmId) throws SQLException {
        try (PreparedStatement ps = conn.prepareStatement(
                "INSERT INTO account_quota (id, cm_id, rolls_allocated, rolls_used) VALUES (?, ?, 0, 0)")) {
            ps.setObject(1, UUID.randomUUID());
            ps.setObject(2, cmId);
            ps.executeUpdate();
        }
    }
}
