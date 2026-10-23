package com.giveaway.giveawaytrustengine.auth;

import com.giveaway.giveawaytrustengine.GiveawayTrustEngineApplication;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Chunk 4 review (second round), item 4: {@link AuthBeanAvailabilityGuard} must fail startup,
 * naming the specific missing bean, if {@link RevocationChecker}, {@link OAuthStateService},
 * {@link CommunityManagerRepository}, or {@link RefreshTokenService} resolves to {@code null} in
 * a real deployment -- but must NOT fire in a context that deliberately excludes Redis/DataSource
 * autoconfiguration (the existing pattern several test classes already use to boot a
 * Redis/DB-less context on purpose).
 *
 * The unit-level tests below use {@link ApplicationContextRunner} with hand-built configurations
 * (same isolation pattern as {@code StartupGuardTest}), registering ONE of the four beans as a
 * direct {@code null} to simulate exactly the failure this guard exists to catch, without needing
 * a real Redis/DataSource outage to reproduce it.
 */
class AuthBeanAvailabilityGuardTest {

    private static RevocationChecker dummyRevocationChecker() {
        return new RevocationChecker(null, null, Clock.systemUTC(), Duration.ofMinutes(15));
    }

    private static OAuthStateService dummyOAuthStateService() {
        return new OAuthStateService(null, Duration.ofMinutes(5));
    }

    private static CommunityManagerRepository dummyCommunityManagerRepository() {
        return new CommunityManagerRepository(null, Clock.systemUTC());
    }

    private static RefreshTokenService dummyRefreshTokenService() {
        return new RefreshTokenService(null, Clock.systemUTC(), dummyRevocationChecker(), null);
    }

    private static Throwable rootCause(AssertableApplicationContext context) {
        Throwable failure = context.getStartupFailure();
        assertThat(failure).as("expected a startup failure but context did not fail").isNotNull();
        Throwable cursor = failure;
        while (cursor.getCause() != null) {
            cursor = cursor.getCause();
        }
        return cursor;
    }

    @Configuration
    static class AllFourPresentExceptRevocationChecker {
        @Bean
        RevocationChecker revocationChecker() {
            return null;
        }

        @Bean
        OAuthStateService oauthStateService() {
            return dummyOAuthStateService();
        }

        @Bean
        CommunityManagerRepository communityManagerRepository() {
            return dummyCommunityManagerRepository();
        }

        @Bean
        RefreshTokenService refreshTokenService() {
            return dummyRefreshTokenService();
        }

        @Bean
        AuthBeanAvailabilityGuard guard(ObjectProvider<RevocationChecker> revocationChecker,
                ObjectProvider<OAuthStateService> oauthStateService,
                ObjectProvider<CommunityManagerRepository> communityManagerRepository,
                ObjectProvider<RefreshTokenService> refreshTokenService) {
            return new AuthBeanAvailabilityGuard(
                    revocationChecker, oauthStateService, communityManagerRepository, refreshTokenService);
        }
    }

    @Test
    void nullRevocationCheckerFailsStartupNamingIt() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFourPresentExceptRevocationChecker.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(IllegalStateException.class);
                    assertThat(root.getMessage()).contains("revocationChecker");
                });
    }

    @Configuration
    static class AllFourPresentExceptOauthStateService {
        @Bean
        RevocationChecker revocationChecker() {
            return dummyRevocationChecker();
        }

        @Bean
        OAuthStateService oauthStateService() {
            return null;
        }

        @Bean
        CommunityManagerRepository communityManagerRepository() {
            return dummyCommunityManagerRepository();
        }

        @Bean
        RefreshTokenService refreshTokenService() {
            return dummyRefreshTokenService();
        }

        @Bean
        AuthBeanAvailabilityGuard guard(ObjectProvider<RevocationChecker> revocationChecker,
                ObjectProvider<OAuthStateService> oauthStateService,
                ObjectProvider<CommunityManagerRepository> communityManagerRepository,
                ObjectProvider<RefreshTokenService> refreshTokenService) {
            return new AuthBeanAvailabilityGuard(
                    revocationChecker, oauthStateService, communityManagerRepository, refreshTokenService);
        }
    }

    @Test
    void nullOauthStateServiceFailsStartupNamingIt() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFourPresentExceptOauthStateService.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(IllegalStateException.class);
                    assertThat(root.getMessage()).contains("oauthStateService");
                });
    }

    @Configuration
    static class AllFourPresentExceptCommunityManagerRepository {
        @Bean
        RevocationChecker revocationChecker() {
            return dummyRevocationChecker();
        }

        @Bean
        OAuthStateService oauthStateService() {
            return dummyOAuthStateService();
        }

        @Bean
        CommunityManagerRepository communityManagerRepository() {
            return null;
        }

        @Bean
        RefreshTokenService refreshTokenService() {
            return dummyRefreshTokenService();
        }

        @Bean
        AuthBeanAvailabilityGuard guard(ObjectProvider<RevocationChecker> revocationChecker,
                ObjectProvider<OAuthStateService> oauthStateService,
                ObjectProvider<CommunityManagerRepository> communityManagerRepository,
                ObjectProvider<RefreshTokenService> refreshTokenService) {
            return new AuthBeanAvailabilityGuard(
                    revocationChecker, oauthStateService, communityManagerRepository, refreshTokenService);
        }
    }

    @Test
    void nullCommunityManagerRepositoryFailsStartupNamingIt() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFourPresentExceptCommunityManagerRepository.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(IllegalStateException.class);
                    assertThat(root.getMessage()).contains("communityManagerRepository");
                });
    }

    @Configuration
    static class AllFourPresentExceptRefreshTokenService {
        @Bean
        RevocationChecker revocationChecker() {
            return dummyRevocationChecker();
        }

        @Bean
        OAuthStateService oauthStateService() {
            return dummyOAuthStateService();
        }

        @Bean
        CommunityManagerRepository communityManagerRepository() {
            return dummyCommunityManagerRepository();
        }

        @Bean
        RefreshTokenService refreshTokenService() {
            return null;
        }

        @Bean
        AuthBeanAvailabilityGuard guard(ObjectProvider<RevocationChecker> revocationChecker,
                ObjectProvider<OAuthStateService> oauthStateService,
                ObjectProvider<CommunityManagerRepository> communityManagerRepository,
                ObjectProvider<RefreshTokenService> refreshTokenService) {
            return new AuthBeanAvailabilityGuard(
                    revocationChecker, oauthStateService, communityManagerRepository, refreshTokenService);
        }
    }

    @Test
    void nullRefreshTokenServiceFailsStartupNamingIt() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFourPresentExceptRefreshTokenService.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(IllegalStateException.class);
                    assertThat(root.getMessage()).contains("refreshTokenService");
                });
    }

    @Configuration
    static class AllFourPresent {
        @Bean
        RevocationChecker revocationChecker() {
            return dummyRevocationChecker();
        }

        @Bean
        OAuthStateService oauthStateService() {
            return dummyOAuthStateService();
        }

        @Bean
        CommunityManagerRepository communityManagerRepository() {
            return dummyCommunityManagerRepository();
        }

        @Bean
        RefreshTokenService refreshTokenService() {
            return dummyRefreshTokenService();
        }

        @Bean
        AuthBeanAvailabilityGuard guard(ObjectProvider<RevocationChecker> revocationChecker,
                ObjectProvider<OAuthStateService> oauthStateService,
                ObjectProvider<CommunityManagerRepository> communityManagerRepository,
                ObjectProvider<RefreshTokenService> refreshTokenService) {
            return new AuthBeanAvailabilityGuard(
                    revocationChecker, oauthStateService, communityManagerRepository, refreshTokenService);
        }
    }

    @Test
    void allFourPresentBootsCleanly() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFourPresent.class)
                .run(context -> assertThat(context).hasNotFailed());
    }

    // Integration-level: the REAL excluded-context pattern (same exclusion flag
    // StartupGuardTest#realApplicationStartsWithDevAndRealSandboxUrl and
    // StructuredLoggingIntegrationTest already rely on) must still boot fine -- the guard must
    // not fire when Redis/DataSource autoconfiguration was deliberately excluded.
    @Test
    void realApplicationWithRedisAndDataSourceExcludedStillBoots() {
        SpringApplicationBuilder builder = new SpringApplicationBuilder(GiveawayTrustEngineApplication.class)
                .web(WebApplicationType.NONE);

        ConfigurableApplicationContext context = builder.run(
                "--spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,"
                        + "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration,"
                        + "org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration",
                "--app.environment=DEV",
                "--app.bachs.sandbox-base-url=https://sandbox-api.bachs.io",
                "--app.bachs.live-base-url=https://api.bachs.io",
                "--app.bachs.base-url=https://sandbox-api.bachs.io",
                "--app.jwt.signing-key=MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MDE=",
                "--app.x-oauth.client-id=fake-client-id",
                "--app.x-oauth.client-secret=fake-client-secret",
                "--app.x-oauth.redirect-uri=https://example.test/auth/callback",
                "--spring.data.redis.password=fake-redis-password");
        try {
            assertThat(context.isActive())
                    .as("the guard must not fail startup when Redis/DataSource autoconfiguration "
                            + "was deliberately excluded")
                    .isTrue();
        } finally {
            context.close();
        }
    }
}
