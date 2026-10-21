package com.giveaway.giveawaytrustengine;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Self-contained: brings up its own Testcontainers Postgres and Redis via
 * {@code @DynamicPropertySource}, so this test needs no .env, no docker-compose stack, and
 * no exported environment variables. Same pattern as
 * {@code schema.FlywayMigrationTest}.
 */
@Testcontainers
@SpringBootTest
class GiveawayTrustEngineApplicationTests {

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
    }

    @Test
    void contextLoads() {
    }

}
