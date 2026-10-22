package com.giveaway.giveawaytrustengine.auth;

import java.time.Clock;
import java.util.UUID;

import javax.sql.DataSource;

/**
 * Rotates refresh tokens and detects reuse. See docs/slices/03-auth.md, Section 2 (rotation)
 * and Section 4 (revocation).
 *
 * RED stub (slice 3): {@link #refresh(String)} always throws {@link UnsupportedOperationException}
 * rather than returning a fixed wrong {@link RefreshResult} -- picked over a fake result because
 * every caller in {@code RefreshTokenConcurrencyTest} either asserts directly on the returned
 * {@link RefreshResult} (a fake value would produce a confusing downstream NullPointerException
 * or wrong-value assertion several lines away from the real problem) or distinguishes
 * {@link ReuseDetectedException} from "any other exception" (an unconditionally-thrown
 * {@code UnsupportedOperationException} lands cleanly in the "any other exception" bucket with
 * an unambiguous message). Real atomic rotation, reuse detection, and whole-family revocation
 * are not implemented yet.
 */
public class RefreshTokenService {

    private final DataSource dataSource;
    private final Clock clock;
    private final RevocationChecker revocationChecker;

    public RefreshTokenService(DataSource dataSource, Clock clock, RevocationChecker revocationChecker) {
        this.dataSource = dataSource;
        this.clock = clock;
        this.revocationChecker = revocationChecker;
    }

    public RefreshResult refresh(String cookieValue) {
        throw new UnsupportedOperationException("not implemented");
    }

    /**
     * Issues the very first refresh token for a brand-new session (called once at login, before
     * any rotation has happened). See docs/slices/03-auth.md, Section 2.
     *
     * RED stub (slice 3): same pattern as {@link #refresh(String)} -- always throws
     * {@link UnsupportedOperationException} rather than returning a fake {@link RefreshResult}.
     * Real token generation, hashing, and insertion are not implemented yet.
     */
    public RefreshResult issueInitialRefreshToken(UUID cmId, UUID familyId) {
        throw new UnsupportedOperationException("not implemented");
    }
}
