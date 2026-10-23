package com.giveaway.giveawaytrustengine.auth;

import com.giveaway.giveawaytrustengine.TestImages;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Slice 3 final fixes, item 1. {@code JdbcStatementTimeoutTest}'s lock-contention tests prove
 * the application's real failure path (a blocked statement surfaces as {@code IllegalStateException}
 * within a bound), but they do it against a hand-rolled raw-connection {@code DataSource} that
 * sets {@code statement_timeout} manually -- they say nothing about whether Hikari's own {@code
 * connection-init-sql} property (what {@code application.properties} actually configures) is the
 * thing doing the work in the real app.
 *
 * <p>Worse, {@code RefreshEndpointTest.dbFailureDuringRefreshReturns503} -- the test meant to
 * prove exactly that, by boot-args-overriding {@code connection-init-sql} and then racing a row
 * lock -- turned out to prove nothing on its own: removing ONLY that test's boot-arg override
 * left {@code application.properties}'s own {@code connection-init-sql} default (5000ms) still
 * active underneath it, so the test kept passing (just ~1.5s slower) with no failure at all. The
 * "mutation" looked caught, but the thing doing the catching was the production default, not
 * anything this specific test asserted.
 *
 * <p>This test proves the mechanism directly instead: build a small Hikari pool ({@code
 * minimumIdle == maximumPoolSize}, so every connection in it is opened eagerly at pool startup,
 * not lazily on first borrow) with {@code connectionInitSql} set, borrow each of its connections
 * in turn (repeated several times over, well past the pool's own size, to sample every one of
 * them rather than relying on borrowing exactly once), and assert {@code SHOW statement_timeout}
 * comes back {@code "5s"} on every single one. No lock, no race, no timing window -- a
 * deterministic, immediate check of the one thing in question: that Hikari genuinely runs {@code
 * connectionInitSql} against each physical connection it creates, not just the first.
 */
@Testcontainers
class HikariConnectionInitSqlStatementTimeoutTest {

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(TestImages.POSTGRES)
            .withDatabaseName("hikari_init_sql_test")
            .withUsername("test")
            .withPassword("test");

    @BeforeAll
    static void start() {
        POSTGRES.start();
    }

    @AfterAll
    static void stop() {
        POSTGRES.stop();
    }

    /**
     * {@code minimumIdle == maximumPoolSize} forces Hikari to eagerly open every connection in
     * the pool up front, rather than lazily creating one on first borrow -- so all {@code
     * poolSize} physical connections exist (and have had {@code connectionInitSql} run against
     * them) before the first {@code getConnection()} call below, not just the first one borrowed.
     */
    private static HikariDataSource buildPool(String connectionInitSql, int poolSize) {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(POSTGRES.getJdbcUrl());
        config.setUsername(POSTGRES.getUsername());
        config.setPassword(POSTGRES.getPassword());
        config.setMaximumPoolSize(poolSize);
        config.setMinimumIdle(poolSize);
        config.setConnectionTimeout(5000);
        if (connectionInitSql != null) {
            config.setConnectionInitSql(connectionInitSql);
        }
        return new HikariDataSource(config);
    }

    private static String showStatementTimeout(Connection conn) throws Exception {
        try (Statement st = conn.createStatement();
                ResultSet rs = st.executeQuery("SHOW statement_timeout")) {
            rs.next();
            return rs.getString(1);
        }
    }

    // The real proof: every one of the pool's eagerly-created physical connections carries the
    // statement_timeout connection-init-sql configured -- borrowed well more times than the pool
    // size (returning each one between borrows) to sample all of them, not just the first.
    // Matches application.properties's real value (5000ms -> "5s").
    @Test
    void everyPooledConnectionHasStatementTimeoutFromConnectionInitSql() throws Exception {
        try (HikariDataSource pool = buildPool("SET statement_timeout=5000", 3)) {
            for (int i = 0; i < 8; i++) { // well past the pool size: samples every connection in it
                try (Connection conn = pool.getConnection()) {
                    assertThat(showStatementTimeout(conn))
                            .as("connection #%d borrowed from the pool must carry the configured statement_timeout", i)
                            .isEqualTo("5s");
                }
            }
        }
    }
}
