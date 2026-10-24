package com.giveaway.giveawaytrustengine.auth;

import com.giveaway.giveawaytrustengine.GiveawayTrustEngineApplication;
import com.giveaway.giveawaytrustengine.quota.AccountQuotaService;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
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
 * {@link CommunityManagerRepository}, {@link RefreshTokenService}, or {@link AccountQuotaService}
 * resolves to {@code null} in a real deployment -- but must NOT fire in a context that
 * deliberately excludes Redis/DataSource autoconfiguration (the existing pattern several test
 * classes already use to boot a Redis/DB-less context on purpose).
 *
 * {@link AccountQuotaService} (slice 4, post-review item 5) was added to this guard's scope
 * alongside the four slice 3 beans -- it depends only on the {@code DataSource}, same category
 * as {@link CommunityManagerRepository}/{@link RefreshTokenService}.
 *
 * The unit-level tests below use {@link ApplicationContextRunner} with hand-built configurations
 * (same isolation pattern as {@code StartupGuardTest}), registering ONE of the five beans as a
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

    private static AccountQuotaService dummyAccountQuotaService() {
        return new AccountQuotaService(null, new SimpleMeterRegistry());
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
    static class AllFivePresentExceptRevocationChecker {
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
        AccountQuotaService accountQuotaService() {
            return dummyAccountQuotaService();
        }

        @Bean
        AuthBeanAvailabilityGuard guard(ObjectProvider<RevocationChecker> revocationChecker,
                ObjectProvider<OAuthStateService> oauthStateService,
                ObjectProvider<CommunityManagerRepository> communityManagerRepository,
                ObjectProvider<RefreshTokenService> refreshTokenService,
                ObjectProvider<AccountQuotaService> accountQuotaService) {
            return new AuthBeanAvailabilityGuard(revocationChecker, oauthStateService,
                    communityManagerRepository, refreshTokenService, accountQuotaService);
        }
    }

    @Test
    void nullRevocationCheckerFailsStartupNamingIt() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFivePresentExceptRevocationChecker.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(IllegalStateException.class);
                    assertThat(root.getMessage()).contains("revocationChecker");
                });
    }

    @Configuration
    static class AllFivePresentExceptOauthStateService {
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
        AccountQuotaService accountQuotaService() {
            return dummyAccountQuotaService();
        }

        @Bean
        AuthBeanAvailabilityGuard guard(ObjectProvider<RevocationChecker> revocationChecker,
                ObjectProvider<OAuthStateService> oauthStateService,
                ObjectProvider<CommunityManagerRepository> communityManagerRepository,
                ObjectProvider<RefreshTokenService> refreshTokenService,
                ObjectProvider<AccountQuotaService> accountQuotaService) {
            return new AuthBeanAvailabilityGuard(revocationChecker, oauthStateService,
                    communityManagerRepository, refreshTokenService, accountQuotaService);
        }
    }

    @Test
    void nullOauthStateServiceFailsStartupNamingIt() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFivePresentExceptOauthStateService.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(IllegalStateException.class);
                    assertThat(root.getMessage()).contains("oauthStateService");
                });
    }

    @Configuration
    static class AllFivePresentExceptCommunityManagerRepository {
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
        AccountQuotaService accountQuotaService() {
            return dummyAccountQuotaService();
        }

        @Bean
        AuthBeanAvailabilityGuard guard(ObjectProvider<RevocationChecker> revocationChecker,
                ObjectProvider<OAuthStateService> oauthStateService,
                ObjectProvider<CommunityManagerRepository> communityManagerRepository,
                ObjectProvider<RefreshTokenService> refreshTokenService,
                ObjectProvider<AccountQuotaService> accountQuotaService) {
            return new AuthBeanAvailabilityGuard(revocationChecker, oauthStateService,
                    communityManagerRepository, refreshTokenService, accountQuotaService);
        }
    }

    @Test
    void nullCommunityManagerRepositoryFailsStartupNamingIt() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFivePresentExceptCommunityManagerRepository.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(IllegalStateException.class);
                    assertThat(root.getMessage()).contains("communityManagerRepository");
                });
    }

    @Configuration
    static class AllFivePresentExceptRefreshTokenService {
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
        AccountQuotaService accountQuotaService() {
            return dummyAccountQuotaService();
        }

        @Bean
        AuthBeanAvailabilityGuard guard(ObjectProvider<RevocationChecker> revocationChecker,
                ObjectProvider<OAuthStateService> oauthStateService,
                ObjectProvider<CommunityManagerRepository> communityManagerRepository,
                ObjectProvider<RefreshTokenService> refreshTokenService,
                ObjectProvider<AccountQuotaService> accountQuotaService) {
            return new AuthBeanAvailabilityGuard(revocationChecker, oauthStateService,
                    communityManagerRepository, refreshTokenService, accountQuotaService);
        }
    }

    @Test
    void nullRefreshTokenServiceFailsStartupNamingIt() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFivePresentExceptRefreshTokenService.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(IllegalStateException.class);
                    assertThat(root.getMessage()).contains("refreshTokenService");
                });
    }

    // ---- Post-review item 5: AccountQuotaService joins this guard's scope ----
    @Configuration
    static class AllFivePresentExceptAccountQuotaService {
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
        AccountQuotaService accountQuotaService() {
            return null;
        }

        @Bean
        AuthBeanAvailabilityGuard guard(ObjectProvider<RevocationChecker> revocationChecker,
                ObjectProvider<OAuthStateService> oauthStateService,
                ObjectProvider<CommunityManagerRepository> communityManagerRepository,
                ObjectProvider<RefreshTokenService> refreshTokenService,
                ObjectProvider<AccountQuotaService> accountQuotaService) {
            return new AuthBeanAvailabilityGuard(revocationChecker, oauthStateService,
                    communityManagerRepository, refreshTokenService, accountQuotaService);
        }
    }

    @Test
    void nullAccountQuotaServiceFailsStartupNamingIt() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFivePresentExceptAccountQuotaService.class)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(IllegalStateException.class);
                    assertThat(root.getMessage()).contains("accountQuotaService");
                });
    }

    @Test
    void accountQuotaServiceNullWithDataSourceExcludedBootsCleanly() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFivePresentExceptAccountQuotaService.class)
                .withPropertyValues("spring.autoconfigure.exclude="
                        + "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Configuration
    static class AllFivePresent {
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
        AccountQuotaService accountQuotaService() {
            return dummyAccountQuotaService();
        }

        @Bean
        AuthBeanAvailabilityGuard guard(ObjectProvider<RevocationChecker> revocationChecker,
                ObjectProvider<OAuthStateService> oauthStateService,
                ObjectProvider<CommunityManagerRepository> communityManagerRepository,
                ObjectProvider<RefreshTokenService> refreshTokenService,
                ObjectProvider<AccountQuotaService> accountQuotaService) {
            return new AuthBeanAvailabilityGuard(revocationChecker, oauthStateService,
                    communityManagerRepository, refreshTokenService, accountQuotaService);
        }
    }

    // Chunk 4 review (final round), item 3: the exclusion check must be exact and per-dependency,
    // not a combined substring OR -- excluding ONLY DataSourceAutoConfiguration must not silence
    // a null OAuthStateService, which depends only on Redis.
    @Test
    void oauthStateServiceNullWithOnlyDataSourceExcludedStillFails() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFivePresentExceptOauthStateService.class)
                .withPropertyValues("spring.autoconfigure.exclude="
                        + "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration")
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(IllegalStateException.class);
                    assertThat(root.getMessage()).contains("oauthStateService");
                });
    }

    @Test
    void oauthStateServiceNullWithRedisExcludedBootsCleanly() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFivePresentExceptOauthStateService.class)
                .withPropertyValues("spring.autoconfigure.exclude="
                        + "org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration")
                .run(context -> assertThat(context).hasNotFailed());
    }

    // Excluding ONLY DataRedisAutoConfiguration must not silence a null
    // CommunityManagerRepository, which depends only on the DataSource.
    @Test
    void communityManagerRepositoryNullWithOnlyRedisExcludedStillFails() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFivePresentExceptCommunityManagerRepository.class)
                .withPropertyValues("spring.autoconfigure.exclude="
                        + "org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration")
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(IllegalStateException.class);
                    assertThat(root.getMessage()).contains("communityManagerRepository");
                });
    }

    @Test
    void communityManagerRepositoryNullWithDataSourceExcludedBootsCleanly() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFivePresentExceptCommunityManagerRepository.class)
                .withPropertyValues("spring.autoconfigure.exclude="
                        + "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void refreshTokenServiceNullWithDataSourceExcludedBootsCleanly() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFivePresentExceptRefreshTokenService.class)
                .withPropertyValues("spring.autoconfigure.exclude="
                        + "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration")
                .run(context -> assertThat(context).hasNotFailed());
    }

    // RevocationChecker depends on BOTH DataSource and Redis -- either one excluded alone
    // already fully explains a null RevocationChecker, so either should silence the guard for
    // this bean specifically (but not for the other three, which is what the tests above prove).
    @Test
    void revocationCheckerNullWithOnlyDataSourceExcludedBootsCleanly() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFivePresentExceptRevocationChecker.class)
                .withPropertyValues("spring.autoconfigure.exclude="
                        + "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration")
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void revocationCheckerNullWithOnlyRedisExcludedBootsCleanly() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFivePresentExceptRevocationChecker.class)
                .withPropertyValues("spring.autoconfigure.exclude="
                        + "org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration")
                .run(context -> assertThat(context).hasNotFailed());
    }

    // A lookalike class name that merely CONTAINS "DataSourceAutoConfiguration" as a substring
    // (but is not an exact, comma-separated entry matching it) must not disable the guard --
    // proving the match is exact-entry, not String.contains(...) against the whole property value.
    @Test
    void lookalikeExclusionPropertyDoesNotDisableGuard() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFivePresentExceptCommunityManagerRepository.class)
                .withPropertyValues("spring.autoconfigure.exclude=com.acme.MyDataSourceAutoConfigurationShim")
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(IllegalStateException.class);
                    assertThat(root.getMessage()).contains("communityManagerRepository");
                });
    }

    @Test
    void allFivePresentBootsCleanly() {
        new ApplicationContextRunner()
                .withUserConfiguration(AllFivePresent.class)
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
