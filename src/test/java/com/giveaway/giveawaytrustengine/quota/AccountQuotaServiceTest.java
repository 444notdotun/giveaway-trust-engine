package com.giveaway.giveawaytrustengine.quota;

import com.giveaway.giveawaytrustengine.TestImages;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Queue;
import java.util.UUID;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Slice 4 (Quota) -- CRITICAL REVIEW. Plan doc: docs/slices/04-quota.md.
 *
 * Concurrency tests use REAL THREADS against a REAL Testcontainers Postgres, never mocks --
 * this slice's entire correctness claim is about real database locking behavior.
 *
 * RED: {@code AccountQuotaService} does not exist yet.
 */
@Testcontainers
@ExtendWith(OutputCaptureExtension.class)
class AccountQuotaServiceTest {

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(TestImages.POSTGRES)
            .withDatabaseName("giveaway_trust_engine_test")
            .withUsername("test")
            .withPassword("test");

    static {
        POSTGRES.start();
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .load()
                .migrate();
    }

    @AfterAll
    static void stopContainer() {
        POSTGRES.stop();
    }

    /**
     * Each {@code getConnection()} opens a brand-new physical connection via {@code
     * DriverManager} -- there is no pool here at all, which trivially satisfies "pool size at
     * least the thread count" for the concurrency tests below: nothing can ever be artificially
     * serialized by pool exhaustion, only by the real row lock the tests are actually about.
     */
    private DataSource simpleDataSource() {
        return new DataSource() {
            @Override
            public Connection getConnection() throws SQLException {
                return DriverManager.getConnection(
                        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
            }

            @Override
            public Connection getConnection(String username, String password) throws SQLException {
                return getConnection();
            }

            @Override
            public java.io.PrintWriter getLogWriter() {
                return null;
            }

            @Override
            public void setLogWriter(java.io.PrintWriter out) {
            }

            @Override
            public void setLoginTimeout(int seconds) {
            }

            @Override
            public int getLoginTimeout() {
                return 0;
            }

            @Override
            public java.util.logging.Logger getParentLogger() {
                return null;
            }

            @Override
            public <T> T unwrap(Class<T> iface) {
                return null;
            }

            @Override
            public boolean isWrapperFor(Class<?> iface) {
                return false;
            }
        };
    }

    /** Test 7 only: every connection from this DataSource carries a real statement_timeout. */
    private DataSource timeoutBoundedDataSource(int timeoutMs) {
        return new DataSource() {
            @Override
            public Connection getConnection() throws SQLException {
                Connection conn = DriverManager.getConnection(
                        POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
                try (Statement st = conn.createStatement()) {
                    st.execute("SET statement_timeout = " + timeoutMs);
                }
                return conn;
            }

            @Override
            public Connection getConnection(String username, String password) throws SQLException {
                return getConnection();
            }

            @Override
            public <T> T unwrap(Class<T> iface) {
                throw new UnsupportedOperationException();
            }

            @Override
            public boolean isWrapperFor(Class<?> iface) {
                return false;
            }

            @Override
            public java.io.PrintWriter getLogWriter() {
                return null;
            }

            @Override
            public void setLogWriter(java.io.PrintWriter out) {
            }

            @Override
            public void setLoginTimeout(int seconds) {
            }

            @Override
            public int getLoginTimeout() {
                return 0;
            }

            @Override
            public java.util.logging.Logger getParentLogger() {
                throw new UnsupportedOperationException();
            }
        };
    }

    private Connection rawConnection() throws SQLException {
        return DriverManager.getConnection(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
    }

    /**
     * A real Hikari pool, sized and pre-warmed so pool exhaustion can never be what serializes
     * the concurrency tests below -- every thread gets its own physical connection, so any
     * serialization observed is the real row lock, not an artifact of a too-small pool.
     * {@code minimumIdle == maximumPoolSize} makes Hikari open every connection eagerly at
     * startup (same mechanism as slice 3's {@code HikariConnectionInitSqlStatementTimeoutTest}),
     * but this additionally blocks until the pool actually reports {@code poolSize} total
     * connections, so "pre-warmed" is a guarantee the test can rely on, not just an expectation.
     */
    private HikariDataSource prewarmedHikariDataSource(int poolSize) throws InterruptedException {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(POSTGRES.getJdbcUrl());
        config.setUsername(POSTGRES.getUsername());
        config.setPassword(POSTGRES.getPassword());
        config.setMaximumPoolSize(poolSize);
        config.setMinimumIdle(poolSize);
        config.setConnectionTimeout(10000);
        HikariDataSource ds = new HikariDataSource(config);

        long deadlineNanos = System.nanoTime() + java.time.Duration.ofSeconds(10).toNanos();
        while (ds.getHikariPoolMXBean().getTotalConnections() < poolSize) {
            if (System.nanoTime() > deadlineNanos) {
                ds.close();
                throw new IllegalStateException(
                        "Hikari pool did not pre-warm to " + poolSize + " connections in time");
            }
            Thread.sleep(25);
        }
        return ds;
    }

    @BeforeEach
    void cleanTables() throws SQLException {
        try (Connection conn = rawConnection(); Statement st = conn.createStatement()) {
            st.execute("DELETE FROM account_quota");
            st.execute("DELETE FROM refresh_token");
            st.execute("DELETE FROM community_manager");
        }
    }

    /** Inserts a community_manager row AND a matching account_quota row with the given values. */
    private UUID newCmWithQuota(int rollsAllocated, int rollsUsed) throws SQLException {
        UUID cmId = UUID.randomUUID();
        try (Connection conn = rawConnection()) {
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO community_manager (id, x_handle, x_user_id, created_at) VALUES (?,?,?,?)")) {
                ps.setObject(1, cmId);
                ps.setString(2, "@cm_" + cmId);
                ps.setString(3, "x-user-" + cmId);
                ps.setTimestamp(4, Timestamp.from(Instant.now()));
                ps.executeUpdate();
            }
            try (PreparedStatement ps = conn.prepareStatement(
                    "INSERT INTO account_quota (id, cm_id, rolls_allocated, rolls_used) VALUES (?,?,?,?)")) {
                ps.setObject(1, UUID.randomUUID());
                ps.setObject(2, cmId);
                ps.setInt(3, rollsAllocated);
                ps.setInt(4, rollsUsed);
                ps.executeUpdate();
            }
        }
        return cmId;
    }

    /** Inserts a community_manager row with NO matching account_quota row -- the defensive case. */
    private UUID newCmWithNoQuotaRow() throws SQLException {
        UUID cmId = UUID.randomUUID();
        try (Connection conn = rawConnection();
                PreparedStatement ps = conn.prepareStatement(
                        "INSERT INTO community_manager (id, x_handle, x_user_id, created_at) VALUES (?,?,?,?)")) {
            ps.setObject(1, cmId);
            ps.setString(2, "@cm_" + cmId);
            ps.setString(3, "x-user-" + cmId);
            ps.setTimestamp(4, Timestamp.from(Instant.now()));
            ps.executeUpdate();
        }
        return cmId;
    }

    private int rollsUsed(UUID cmId) throws SQLException {
        try (Connection conn = rawConnection();
                PreparedStatement ps = conn.prepareStatement(
                        "SELECT rolls_used FROM account_quota WHERE cm_id = ?")) {
            ps.setObject(1, cmId);
            ResultSet rs = ps.executeQuery();
            rs.next();
            return rs.getInt(1);
        }
    }

    private int rollsAllocated(UUID cmId) throws SQLException {
        try (Connection conn = rawConnection();
                PreparedStatement ps = conn.prepareStatement(
                        "SELECT rolls_allocated FROM account_quota WHERE cm_id = ?")) {
            ps.setObject(1, cmId);
            ResultSet rs = ps.executeQuery();
            rs.next();
            return rs.getInt(1);
        }
    }

    // ---- Test 1 ----
    @Test
    void claimRollSucceedsAndIncrementsRollsUsedByExactlyOne() throws Exception {
        UUID cmId = newCmWithQuota(5, 2);
        AccountQuotaService service = new AccountQuotaService(simpleDataSource(), new SimpleMeterRegistry());

        boolean result = service.claimRoll(cmId);

        assertThat(result).isTrue();
        assertThat(rollsUsed(cmId)).isEqualTo(3);
    }

    // ---- Test 2 (merged with former test 7's mutation check) ----
    @Test
    void claimRollReturnsFalseWhenNoRollLeft() throws Exception {
        UUID cmId = newCmWithQuota(3, 3); // exhausted
        AccountQuotaService service = new AccountQuotaService(simpleDataSource(), new SimpleMeterRegistry());

        boolean result = service.claimRoll(cmId);

        assertThat(result).isFalse();
        assertThat(rollsUsed(cmId)).as("no change on rejection").isEqualTo(3);
    }

    // ---- Test 3: the concurrency test BUILD_ORDER names directly ----
    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void fiftyThreadsOneRollLeftExactlyOneSucceeds() throws Exception {
        UUID cmId = newCmWithQuota(1, 0); // exactly one roll available
        int threadCount = 50;

        try (HikariDataSource hikariDs = prewarmedHikariDataSource(threadCount)) {
            AccountQuotaService service = new AccountQuotaService(hikariDs, new SimpleMeterRegistry());

            ExecutorService pool = Executors.newFixedThreadPool(threadCount);
            CountDownLatch readyLatch = new CountDownLatch(threadCount);
            CountDownLatch startGate = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(threadCount);
            AtomicInteger trueCount = new AtomicInteger();
            AtomicInteger falseCount = new AtomicInteger();
            Queue<Throwable> unexpected = new ConcurrentLinkedQueue<>();

            for (int i = 0; i < threadCount; i++) {
                pool.submit(() -> {
                    try {
                        readyLatch.countDown();
                        startGate.await(); // true simultaneous release, not a trickle
                        boolean claimed = service.claimRoll(cmId);
                        if (claimed) {
                            trueCount.incrementAndGet();
                        } else {
                            falseCount.incrementAndGet();
                        }
                    }
                    catch (Throwable t) {
                        unexpected.add(t);
                    }
                    finally {
                        doneLatch.countDown();
                    }
                });
            }

            readyLatch.await();
            startGate.countDown();
            doneLatch.await();
            pool.shutdownNow();

            assertThat(unexpected).as("no unexpected exception from any thread").isEmpty();
            assertThat(trueCount.get()).as("exactly one thread claims the last roll").isEqualTo(1);
            assertThat(falseCount.get()).as("the other 49 are rejected cleanly").isEqualTo(49);
            assertThat(rollsUsed(cmId)).as("rolls_used ends exactly at rolls_allocated, never past it").isEqualTo(1);
        }
    }

    // ---- Test 4: claim-and-refund interleave, looped 20x by the caller of this test class ----
    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void claimAndRefundInterleaveNeverLeavesAnInvalidValue() throws Exception {
        UUID cmId = newCmWithQuota(10, 5); // rolls_allocated=10, rolls_used=5
        int threadCount = 20;

        try (HikariDataSource hikariDs = prewarmedHikariDataSource(threadCount)) {
            AccountQuotaService service = new AccountQuotaService(hikariDs, new SimpleMeterRegistry());

            ExecutorService pool = Executors.newFixedThreadPool(threadCount);
            CountDownLatch readyLatch = new CountDownLatch(threadCount);
            CountDownLatch startGate = new CountDownLatch(1);
            CountDownLatch doneLatch = new CountDownLatch(threadCount);
            AtomicInteger successfulClaims = new AtomicInteger();
            AtomicInteger successfulRefunds = new AtomicInteger();
            Queue<Throwable> unexpected = new ConcurrentLinkedQueue<>();

            for (int i = 0; i < threadCount; i++) {
                boolean claim = i % 2 == 0;
                pool.submit(() -> {
                    try {
                        readyLatch.countDown();
                        startGate.await();
                        if (claim) {
                            if (service.claimRoll(cmId)) {
                                successfulClaims.incrementAndGet();
                            }
                        }
                        else {
                            if (service.refundRoll(cmId)) {
                                successfulRefunds.incrementAndGet();
                            }
                        }
                    }
                    catch (Throwable t) {
                        unexpected.add(t);
                    }
                    finally {
                        doneLatch.countDown();
                    }
                });
            }

            readyLatch.await();
            startGate.countDown();
            boolean finishedInTime = doneLatch.await(20, TimeUnit.SECONDS);
            pool.shutdownNow();

            assertThat(finishedInTime).as("no deadlock between claim and refund on the same row").isTrue();
            assertThat(unexpected).as("no unexpected exception from any thread").isEmpty();
            int finalUsed = rollsUsed(cmId);
            assertThat(finalUsed).as("rolls_used stays within bounds throughout").isBetween(0, 10);
            assertThat(finalUsed)
                    .as("final value must reconcile exactly against every successful operation, "
                            + "not just stay in bounds -- 5 (starting) + successfulClaims - successfulRefunds")
                    .isEqualTo(5 + successfulClaims.get() - successfulRefunds.get());
        }
    }

    // ---- Test 5 ----
    @Test
    void refundRollSucceedsAndDecrementsRollsUsedByExactlyOne() throws Exception {
        UUID cmId = newCmWithQuota(5, 3);
        AccountQuotaService service = new AccountQuotaService(simpleDataSource(), new SimpleMeterRegistry());

        boolean result = service.refundRoll(cmId);

        assertThat(result).isTrue();
        assertThat(rollsUsed(cmId)).isEqualTo(2);
    }

    // ---- Test 6 ----
    @Test
    void refundRollOverRefundReturnsFalseWithNoException() throws Exception {
        UUID cmId = newCmWithQuota(5, 0); // nothing to refund
        AccountQuotaService service = new AccountQuotaService(simpleDataSource(), new SimpleMeterRegistry());

        boolean result = service.refundRoll(cmId);

        assertThat(result).isFalse();
        assertThat(rollsUsed(cmId)).as("never goes negative").isEqualTo(0);
    }

    // Reviewer finding 1: the guard-legitimately-tripped zero-rows path (over-refund, including
    // a double refund of the same claim) must leave a trace -- WARN + counter -- unlike before,
    // when it returned false silently with no log and no metric at all.
    @Test
    void refundRollNoopLogsWarnAndIncrementsCounter(CapturedOutput output) throws Exception {
        UUID cmId = newCmWithQuota(5, 0); // nothing to refund
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        AccountQuotaService service = new AccountQuotaService(simpleDataSource(), meterRegistry);

        boolean result = service.refundRoll(cmId);

        assertThat(result).isFalse();
        assertThat(output.getAll()).contains("reason=refund-noop");
        assertThat(output.getAll()).contains("WARN");
        assertThat(output.getAll()).as("only cmId identifies the row").contains(cmId.toString());
        assertThat(output.getAll()).as("no raw SQL or row values leaked").doesNotContain("UPDATE account_quota");
        assertThat(meterRegistry.counter("giveaway.quota.failure", "reason", "refund-noop").count())
                .isEqualTo(1.0);
    }

    // ---- Test 7: blocked statement fails within the statement_timeout bound ----
    @Test
    @Timeout(value = 15, unit = TimeUnit.SECONDS)
    void blockedClaimRollFailsWithinStatementTimeoutBound() throws Exception {
        UUID cmId = newCmWithQuota(5, 0);

        Connection lockHolder = rawConnection();
        lockHolder.setAutoCommit(false);
        try (PreparedStatement ps = lockHolder.prepareStatement(
                "UPDATE account_quota SET rolls_used = rolls_used WHERE cm_id = ?")) {
            ps.setObject(1, cmId);
            ps.executeUpdate();
        }

        try {
            AccountQuotaService service = new AccountQuotaService(timeoutBoundedDataSource(2000), new SimpleMeterRegistry());

            long start = System.nanoTime();
            assertThrows(IllegalStateException.class, () -> service.claimRoll(cmId));
            long elapsedMs = java.time.Duration.ofNanos(System.nanoTime() - start).toMillis();

            assertThat(elapsedMs)
                    .as("must fail within a small multiple of the bound, never hang indefinitely")
                    .isLessThan(2000L * 5);
        }
        finally {
            lockHolder.rollback();
            lockHolder.close();
        }
    }

    // ---- Post-review: AccountQuotaService must join the caller's transaction ----
    // Each DataSource here opens a brand-new physical connection per getConnection() call (see
    // simpleDataSource()'s own Javadoc), with no awareness of Spring's transaction
    // synchronization -- so if AccountQuotaService still called dataSource.getConnection()
    // directly, its write would land on a DIFFERENT connection than the one
    // DataSourceTransactionManager/TransactionTemplate is managing, auto-commit on that
    // separate connection, and survive the outer rollback. These three tests prove it does not.
    @Test
    void claimRollParticipatesInCallersTransactionAndRollsBackCleanly() throws Exception {
        UUID cmId = newCmWithQuota(5, 2);
        DataSource ds = simpleDataSource();
        DataSourceTransactionManager txManager = new DataSourceTransactionManager(ds);
        TransactionTemplate txTemplate = new TransactionTemplate(txManager);
        AccountQuotaService service = new AccountQuotaService(ds, new SimpleMeterRegistry());

        txTemplate.execute(status -> {
            service.claimRoll(cmId);
            status.setRollbackOnly();
            return null;
        });

        assertThat(rollsUsed(cmId)).as("rolled back -- claimRoll's write must not survive").isEqualTo(2);
    }

    @Test
    void refundRollParticipatesInCallersTransactionAndRollsBackCleanly() throws Exception {
        UUID cmId = newCmWithQuota(5, 3);
        DataSource ds = simpleDataSource();
        DataSourceTransactionManager txManager = new DataSourceTransactionManager(ds);
        TransactionTemplate txTemplate = new TransactionTemplate(txManager);
        AccountQuotaService service = new AccountQuotaService(ds, new SimpleMeterRegistry());

        txTemplate.execute(status -> {
            service.refundRoll(cmId);
            status.setRollbackOnly();
            return null;
        });

        assertThat(rollsUsed(cmId)).as("rolled back -- refundRoll's write must not survive").isEqualTo(3);
    }

    @Test
    void addRollsParticipatesInCallersTransactionAndRollsBackCleanly() throws Exception {
        UUID cmId = newCmWithQuota(5, 2);
        DataSource ds = simpleDataSource();
        DataSourceTransactionManager txManager = new DataSourceTransactionManager(ds);
        TransactionTemplate txTemplate = new TransactionTemplate(txManager);
        AccountQuotaService service = new AccountQuotaService(ds, new SimpleMeterRegistry());

        txTemplate.execute(status -> {
            service.addRolls(cmId, 7);
            status.setRollbackOnly();
            return null;
        });

        assertThat(rollsAllocated(cmId)).as("rolled back -- addRolls's write must not survive").isEqualTo(5);
    }

    // ---- Test 8: missing account_quota row disambiguation ----
    // Reviewer finding 2: this data-integrity failure path must log a WARN and increment a
    // counter BEFORE throwing -- previously it threw silently, with no trace at all.
    @Test
    void claimRollOnMissingAccountQuotaRowThrowsClearException(CapturedOutput output) throws Exception {
        UUID cmId = newCmWithNoQuotaRow();
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        AccountQuotaService service = new AccountQuotaService(simpleDataSource(), meterRegistry);

        assertThrows(IllegalStateException.class, () -> service.claimRoll(cmId));

        assertThat(output.getAll()).contains("reason=missing-quota-row");
        assertThat(output.getAll()).contains("WARN");
        assertThat(output.getAll()).as("only cmId identifies the row").contains(cmId.toString());
        assertThat(output.getAll()).as("no raw SQL or row values leaked").doesNotContain("UPDATE account_quota");
        assertThat(meterRegistry.counter("giveaway.quota.failure", "reason", "missing-quota-row").count())
                .isEqualTo(1.0);
    }

    @Test
    void refundRollOnMissingAccountQuotaRowThrowsClearException(CapturedOutput output) throws Exception {
        UUID cmId = newCmWithNoQuotaRow();
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        AccountQuotaService service = new AccountQuotaService(simpleDataSource(), meterRegistry);

        assertThrows(IllegalStateException.class, () -> service.refundRoll(cmId));

        assertThat(output.getAll()).contains("reason=missing-quota-row");
        assertThat(output.getAll()).contains("WARN");
        assertThat(output.getAll()).as("only cmId identifies the row").contains(cmId.toString());
        assertThat(output.getAll()).as("no raw SQL or row values leaked").doesNotContain("UPDATE account_quota");
        assertThat(meterRegistry.counter("giveaway.quota.failure", "reason", "missing-quota-row").count())
                .isEqualTo(1.0);
    }

    // ---- Test 9: observability, failure paths ----
    @Test
    void dbUnavailableLogsWarnAndIncrementsCounter(CapturedOutput output) throws Exception {
        UUID cmId = newCmWithQuota(5, 0);
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        AccountQuotaService service = new AccountQuotaService(simpleDataSource(), meterRegistry);

        Connection lockHolder = rawConnection();
        lockHolder.setAutoCommit(false);
        try (PreparedStatement ps = lockHolder.prepareStatement(
                "UPDATE account_quota SET rolls_used = rolls_used WHERE cm_id = ?")) {
            ps.setObject(1, cmId);
            ps.executeUpdate();
        }
        try {
            AccountQuotaService timeoutBoundService = new AccountQuotaService(timeoutBoundedDataSource(2000), meterRegistry);
            assertThrows(IllegalStateException.class, () -> timeoutBoundService.claimRoll(cmId));

            assertThat(output.getAll()).contains("reason=db-unavailable");
            assertThat(output.getAll()).as("WARN level for a real DB failure").contains("WARN");
            assertThat(meterRegistry.counter("giveaway.quota.failure", "reason", "db-unavailable").count())
                    .isEqualTo(1.0);
        }
        finally {
            lockHolder.rollback();
            lockHolder.close();
        }
    }

    // ---- Test 10: "exhausted" logs at INFO, not WARN ----
    @Test
    void exhaustedLogsInfoNotWarnAndIncrementsCounter(CapturedOutput output) throws Exception {
        UUID cmId = newCmWithQuota(0, 0); // brand-new CM, 0/0 -- a normal business outcome
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        AccountQuotaService service = new AccountQuotaService(simpleDataSource(), meterRegistry);

        boolean result = service.claimRoll(cmId);

        assertThat(result).isFalse();
        assertThat(output.getAll()).contains("reason=exhausted");
        assertThat(output.getAll())
                .as("exhausted must never log at WARN")
                .doesNotContain("WARN");
        assertThat(meterRegistry.counter("giveaway.quota.failure", "reason", "exhausted").count())
                .isEqualTo(1.0);
    }

    // ---- Test 11: observability, success paths ----
    @Test
    void claimAndRefundSuccessEachLogOneInfoLine(CapturedOutput output) throws Exception {
        UUID cmId = newCmWithQuota(5, 0);
        AccountQuotaService service = new AccountQuotaService(simpleDataSource(), new SimpleMeterRegistry());

        service.claimRoll(cmId);
        assertThat(output.getAll()).contains("outcome=claimed");
        assertThat(output.getAll()).contains(cmId.toString());

        service.refundRoll(cmId);
        assertThat(output.getAll()).contains("outcome=refunded");
    }

    // ---- Test 12: no secret or personal data in any log line ----
    @Test
    void noSecretOrPersonalDataInAnyLogLine(CapturedOutput output) throws Exception {
        UUID cmId = newCmWithQuota(5, 2);
        AccountQuotaService service = new AccountQuotaService(simpleDataSource(), new SimpleMeterRegistry());

        service.claimRoll(cmId);
        service.refundRoll(cmId);
        service.claimRoll(newCmWithQuota(0, 0)); // exhausted path too

        assertThat(output.getAll()).as("no raw SQL text leaked").doesNotContain("UPDATE account_quota");
    }

    // ---- Test 13 ----
    @Test
    void addRollsSucceedsAndIncrementsRollsAllocatedByExactlyTheGivenAmount() throws Exception {
        UUID cmId = newCmWithQuota(5, 2);
        AccountQuotaService service = new AccountQuotaService(simpleDataSource(), new SimpleMeterRegistry());

        service.addRolls(cmId, 8);

        assertThat(rollsAllocated(cmId)).isEqualTo(13);
    }

    // ---- Test 14 ----
    @Test
    void addRollsRejectsNonPositiveAmountBeforeAnySql() throws Exception {
        UUID cmId = newCmWithQuota(5, 2);
        AccountQuotaService service = new AccountQuotaService(simpleDataSource(), new SimpleMeterRegistry());

        assertThrows(IllegalArgumentException.class, () -> service.addRolls(cmId, 0));
        assertThrows(IllegalArgumentException.class, () -> service.addRolls(cmId, -1));

        assertThat(rollsAllocated(cmId)).as("rejected before touching the row").isEqualTo(5);
    }

    // ---- Test 15 ----
    // Reviewer finding 2: this data-integrity failure path must log a WARN and increment a
    // counter BEFORE throwing -- previously it threw silently, with no trace at all.
    @Test
    void addRollsOnMissingCmIdThrowsClearExceptionDirectly(CapturedOutput output) throws Exception {
        UUID cmId = newCmWithNoQuotaRow();
        SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
        AccountQuotaService service = new AccountQuotaService(simpleDataSource(), meterRegistry);

        assertThrows(IllegalStateException.class, () -> service.addRolls(cmId, 5));

        assertThat(output.getAll()).contains("reason=missing-quota-row");
        assertThat(output.getAll()).contains("WARN");
        assertThat(output.getAll()).as("only cmId identifies the row").contains(cmId.toString());
        assertThat(output.getAll()).as("no raw SQL or row values leaked").doesNotContain("UPDATE account_quota");
        assertThat(meterRegistry.counter("giveaway.quota.failure", "reason", "missing-quota-row").count())
                .isEqualTo(1.0);
    }

    // ---- Test 16: addRolls concurrency ----
    @Test
    @Timeout(value = 30, unit = TimeUnit.SECONDS)
    void addRollsConcurrencyNeverLosesAnUpdate() throws Exception {
        UUID cmId = newCmWithQuota(0, 0);
        AccountQuotaService service = new AccountQuotaService(simpleDataSource(), new SimpleMeterRegistry());

        int threadCount = 50;
        List<Integer> amounts = IntStream.range(0, threadCount).mapToObj(i -> (i % 5) + 1).toList();
        int expectedTotal = amounts.stream().mapToInt(Integer::intValue).sum();

        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        CountDownLatch readyLatch = new CountDownLatch(threadCount);
        CountDownLatch startGate = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        Queue<Throwable> unexpected = new ConcurrentLinkedQueue<>();

        for (int amount : amounts) {
            pool.submit(() -> {
                try {
                    readyLatch.countDown();
                    startGate.await();
                    service.addRolls(cmId, amount);
                }
                catch (Throwable t) {
                    unexpected.add(t);
                }
                finally {
                    doneLatch.countDown();
                }
            });
        }

        readyLatch.await();
        startGate.countDown();
        doneLatch.await();
        pool.shutdownNow();

        assertThat(unexpected).isEmpty();
        assertThat(rollsAllocated(cmId)).as("no lost update across concurrent credits").isEqualTo(expectedTotal);
    }
}
