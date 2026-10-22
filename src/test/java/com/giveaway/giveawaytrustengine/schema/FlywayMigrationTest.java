package com.giveaway.giveawaytrustengine.schema;

import com.giveaway.giveawaytrustengine.TestImages;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Slice 1 plan (docs/slices/01-migrations-and-schema.md), "Tests" section: Flyway applies V1
 * cleanly to an empty Testcontainers Postgres database and the Spring context starts
 * successfully with ddl-auto=validate against the result.
 *
 * This slice adds no JPA @Entity classes, so ddl-auto=validate has nothing to validate against
 * yet and passes trivially as long as the context starts. It does NOT yet prove Hibernate's
 * entity mappings agree with the schema -- that check only becomes meaningful once a later
 * slice introduces entities. What this test does prove: Flyway applies V1 without error against
 * a real Postgres, and the context can start on top of the result.
 */
@Testcontainers
@SpringBootTest
class FlywayMigrationTest {

    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>(TestImages.POSTGRES)
            .withDatabaseName("giveaway_trust_engine")
            .withUsername("test")
            .withPassword("test");

    static final GenericContainer<?> REDIS = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
            .withExposedPorts(6379);

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
        registry.add("app.environment", () -> "DEV");
        registry.add("app.bachs.sandbox-base-url", () -> "https://sandbox-api.bachs.io");
        registry.add("app.bachs.live-base-url", () -> "https://api.bachs.io");
        registry.add("app.bachs.base-url", () -> "https://sandbox-api.bachs.io");
        registry.add("app.jwt.signing-key", () -> "MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=");
    }

    @org.springframework.beans.factory.annotation.Autowired
    DataSource dataSource;

    // PRD section 3/14/15/17: Flyway must own schema creation; ddl-auto stays validate.
    @Test
    void flywayAppliesV1CleanlyAndContextStartsWithDdlAutoValidate() throws SQLException {
        try (Connection conn = dataSource.getConnection()) {
            assertTrue(tableExists(conn, "flyway_schema_history"),
                    "expected Flyway to have run and recorded its history table "
                            + "('flyway_schema_history') -- an operator checking schema "
                            + "version would find none; this proves no V1 migration ran yet");

            List<String> missing = new ArrayList<>();
            for (String table : List.of("community_manager", "account_quota", "giveaway",
                    "giveaway_entry", "refresh_token", "payment_event", "giveaway_logs")) {
                if (!tableExists(conn, table)) {
                    missing.add(table);
                }
            }
            assertTrue(missing.isEmpty(),
                    "expected all seven domain tables from V1 to exist after Flyway ran; "
                            + "missing: " + missing + " -- the migration under "
                            + "src/main/resources/db/migration has not been written yet");
        }
    }

    private static boolean tableExists(Connection conn, String tableName) throws SQLException {
        try (Statement st = conn.createStatement();
             ResultSet rs = st.executeQuery(
                     "SELECT to_regclass('public." + tableName + "') IS NOT NULL AS exists")) {
            if (!rs.next()) {
                fail("expected a result row checking existence of table " + tableName);
            }
            return rs.getBoolean("exists");
        }
    }
}
