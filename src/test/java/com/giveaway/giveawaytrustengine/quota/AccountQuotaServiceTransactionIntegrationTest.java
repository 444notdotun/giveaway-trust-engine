package com.giveaway.giveawaytrustengine.quota;

import com.giveaway.giveawaytrustengine.TestImages;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Slice 4 (Quota), post-review item 5 follow-up. Every other transaction-participation test
 * (see {@code AccountQuotaServiceTest}'s three
 * {@code *ParticipatesInCallersTransactionAndRollsBackCleanly} tests) builds its own hand-rolled
 * {@code DataSourceTransactionManager} and a plain {@code DataSource}. That proves {@link
 * AccountQuotaService} joins a Spring-managed transaction in general, but not that it actually
 * joins the ONE transaction manager the real, booted application uses.
 *
 * <p>This test boots the real application (Testcontainers Postgres + Redis, same pattern as
 * {@code FlywayMigrationTest}) and autowires the real {@link PlatformTransactionManager} bean --
 * confirmed directly (by probing a booted context) to be {@code
 * org.springframework.orm.jpa.JpaTransactionManager}, registered by Spring Boot's JPA
 * auto-configuration once {@code spring-boot-starter-data-jpa} is on the classpath and a {@code
 * DataSource} exists, even with zero {@code @Entity} classes in this project -- NOT {@code
 * DataSourceTransactionManager}, which is what the unit-level tests use and what might otherwise
 * be assumed. {@code AccountQuotaService}'s own code never checks which transaction manager
 * implementation is active; it only calls {@code DataSourceUtils.getConnection}/{@code
 * releaseConnection} against the {@code DataSource}, so this test is the proof that {@code
 * JpaTransactionManager}'s own connection-binding (done specifically to support mixed JPA/JDBC
 * access to the same database) is what actually makes this work in the real app, not an assumed
 * detail.
 */
@Testcontainers
@SpringBootTest
class AccountQuotaServiceTransactionIntegrationTest {

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(TestImages.POSTGRES)
            .withDatabaseName("giveaway_trust_engine")
            .withUsername("test")
            .withPassword("test");

    private static final String REDIS_PASSWORD = "test-redis-password";

    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse(TestImages.REDIS))
            .withExposedPorts(6379)
            .withCommand("redis-server", "--requirepass", REDIS_PASSWORD);

    static {
        POSTGRES.start();
        REDIS.start();
    }

    @DynamicPropertySource
    static void overrideDatasourceAndRedis(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.data.redis.host", REDIS::getHost);
        registry.add("spring.data.redis.port", () -> REDIS.getMappedPort(6379));
        registry.add("spring.data.redis.password", () -> REDIS_PASSWORD);
        registry.add("app.environment", () -> "DEV");
        registry.add("app.bachs.sandbox-base-url", () -> "https://sandbox-api.bachs.io");
        registry.add("app.bachs.live-base-url", () -> "https://api.bachs.io");
        registry.add("app.bachs.base-url", () -> "https://sandbox-api.bachs.io");
        registry.add("app.jwt.signing-key", () -> "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=");
        registry.add("app.x-oauth.client-id", () -> "fake-client-id");
        registry.add("app.x-oauth.client-secret", () -> "fake-client-secret");
        registry.add("app.x-oauth.redirect-uri", () -> "https://example.test/auth/callback");
    }

    @Autowired
    AccountQuotaService accountQuotaService;

    @Autowired
    PlatformTransactionManager transactionManager;

    @Autowired
    DataSource dataSource;

    private UUID cmId;

    @BeforeEach
    void insertFreshCommunityManagerAndQuota() throws SQLException {
        cmId = UUID.randomUUID();
        try (Connection conn = dataSource.getConnection()) {
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
                ps.setInt(3, 10);
                ps.setInt(4, 5);
                ps.executeUpdate();
            }
        }
    }

    private int rollsUsed() throws SQLException {
        try (Connection conn = dataSource.getConnection();
                PreparedStatement ps = conn.prepareStatement(
                        "SELECT rolls_used FROM account_quota WHERE cm_id = ?")) {
            ps.setObject(1, cmId);
            ResultSet rs = ps.executeQuery();
            rs.next();
            return rs.getInt(1);
        }
    }

    private int rollsAllocated() throws SQLException {
        try (Connection conn = dataSource.getConnection();
                PreparedStatement ps = conn.prepareStatement(
                        "SELECT rolls_allocated FROM account_quota WHERE cm_id = ?")) {
            ps.setObject(1, cmId);
            ResultSet rs = ps.executeQuery();
            rs.next();
            return rs.getInt(1);
        }
    }

    @Test
    void claimRollParticipatesInRealAppTransactionAndRollsBackCleanly() throws Exception {
        TransactionTemplate txTemplate = new TransactionTemplate(transactionManager);

        txTemplate.execute(status -> {
            accountQuotaService.claimRoll(cmId);
            status.setRollbackOnly();
            return null;
        });

        assertThat(rollsUsed()).as("rolled back under the real app's transaction manager").isEqualTo(5);
    }

    @Test
    void refundRollParticipatesInRealAppTransactionAndRollsBackCleanly() throws Exception {
        TransactionTemplate txTemplate = new TransactionTemplate(transactionManager);

        txTemplate.execute(status -> {
            accountQuotaService.refundRoll(cmId);
            status.setRollbackOnly();
            return null;
        });

        assertThat(rollsUsed()).as("rolled back under the real app's transaction manager").isEqualTo(5);
    }

    @Test
    void addRollsParticipatesInRealAppTransactionAndRollsBackCleanly() throws Exception {
        TransactionTemplate txTemplate = new TransactionTemplate(transactionManager);

        txTemplate.execute(status -> {
            accountQuotaService.addRolls(cmId, 7);
            status.setRollbackOnly();
            return null;
        });

        assertThat(rollsAllocated()).as("rolled back under the real app's transaction manager").isEqualTo(10);
    }
}
