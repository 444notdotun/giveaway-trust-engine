package com.giveaway.giveawaytrustengine.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Chunk 4 review (second round), item 4. {@link AuthBeansConfig}'s four {@code @Bean} methods
 * deliberately return {@code null} (via {@code ObjectProvider.getIfAvailable()}) when Redis or
 * the DataSource are not wired -- a handful of test contexts rely on exactly that to boot a
 * Redis/DB-less application on purpose (see {@code StartupGuardTest#realApplicationStartsWithDevAndRealSandboxUrl},
 * {@code StructuredLoggingIntegrationTest}).
 *
 * <p>In the real application, though, a {@code null} here is not a valid configuration -- it
 * means Redis or the DataSource failed to wire up for some other reason, and every one of these
 * beans is used unconditionally on the request path. Left unchecked, the failure would surface
 * much later and much less clearly, as a {@code NullPointerException} the first time a request
 * actually needs the bean. This fails fast instead, at startup, naming exactly which bean never
 * resolved.
 *
 * <p>Chunk 4 review (final round), item 3: the exclusion check is exact and per-dependency, not
 * a combined substring flag. {@code spring.autoconfigure.exclude} is split on commas and each
 * entry compared by exact string equality against the two known autoconfiguration class names --
 * never {@code String.contains(...)} against the whole property value, which would treat a
 * lookalike class name (e.g. {@code com.acme.MyDataSourceAutoConfigurationShim}) as a real
 * exclusion. Each bean is checked against only the exclusion that actually explains its own
 * {@code null}: {@link OAuthStateService} depends only on Redis, {@link CommunityManagerRepository}
 * and {@link RefreshTokenService} depend only on the DataSource, and {@link RevocationChecker}
 * depends on both (so either exclusion alone already fully explains a null RevocationChecker).
 */
@Component
public class AuthBeanAvailabilityGuard implements SmartInitializingSingleton, EnvironmentAware {

    private static final Logger log = LoggerFactory.getLogger(AuthBeanAvailabilityGuard.class);

    private static final String DATASOURCE_AUTOCONFIGURATION_CLASS =
            "org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration";
    private static final String REDIS_AUTOCONFIGURATION_CLASS =
            "org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration";

    private final ObjectProvider<RevocationChecker> revocationChecker;
    private final ObjectProvider<OAuthStateService> oauthStateService;
    private final ObjectProvider<CommunityManagerRepository> communityManagerRepository;
    private final ObjectProvider<RefreshTokenService> refreshTokenService;
    private Environment environment;

    public AuthBeanAvailabilityGuard(ObjectProvider<RevocationChecker> revocationChecker,
            ObjectProvider<OAuthStateService> oauthStateService,
            ObjectProvider<CommunityManagerRepository> communityManagerRepository,
            ObjectProvider<RefreshTokenService> refreshTokenService) {
        this.revocationChecker = revocationChecker;
        this.oauthStateService = oauthStateService;
        this.communityManagerRepository = communityManagerRepository;
        this.refreshTokenService = refreshTokenService;
    }

    @Override
    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    @Override
    public void afterSingletonsInstantiated() {
        boolean dataSourceExcluded = isExcluded(DATASOURCE_AUTOCONFIGURATION_CLASS);
        boolean redisExcluded = isExcluded(REDIS_AUTOCONFIGURATION_CLASS);

        if (!(dataSourceExcluded || redisExcluded)) {
            requireResolved("revocationChecker", revocationChecker.getIfAvailable());
        }
        if (!redisExcluded) {
            requireResolved("oauthStateService", oauthStateService.getIfAvailable());
        }
        if (!dataSourceExcluded) {
            requireResolved("communityManagerRepository", communityManagerRepository.getIfAvailable());
            requireResolved("refreshTokenService", refreshTokenService.getIfAvailable());
        }
    }

    private boolean isExcluded(String autoConfigurationClassName) {
        String excludes = environment.getProperty("spring.autoconfigure.exclude", "");
        for (String entry : excludes.split(",")) {
            if (entry.trim().equals(autoConfigurationClassName)) {
                return true;
            }
        }
        return false;
    }

    private void requireResolved(String beanName, Object bean) {
        if (bean == null) {
            String message = beanName + " resolved to null at startup. Its required infrastructure "
                    + "(Redis and/or the DataSource) was not excluded via spring.autoconfigure.exclude, "
                    + "so this bean is expected to be available; refusing to start rather than risk a "
                    + "NullPointerException on first use.";
            log.error("auth bean availability guard refused to start: bean={}", beanName);
            throw new IllegalStateException(message);
        }
    }
}
