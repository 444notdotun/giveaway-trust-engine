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
 * <p>The two situations are told apart by whether {@code spring.autoconfigure.exclude} names
 * {@code DataSourceAutoConfiguration} or {@code DataRedisAutoConfiguration} -- the same flag the
 * excluded-context tests already set to get a Redis/DB-less boot. If that flag is present, a
 * {@code null} bean is expected and this guard stays quiet; otherwise a {@code null} bean is a
 * startup-time bug.
 */
@Component
public class AuthBeanAvailabilityGuard implements SmartInitializingSingleton, EnvironmentAware {

    private static final Logger log = LoggerFactory.getLogger(AuthBeanAvailabilityGuard.class);

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
        if (infrastructureDeliberatelyExcluded()) {
            return;
        }
        requireResolved("revocationChecker", revocationChecker.getIfAvailable());
        requireResolved("oauthStateService", oauthStateService.getIfAvailable());
        requireResolved("communityManagerRepository", communityManagerRepository.getIfAvailable());
        requireResolved("refreshTokenService", refreshTokenService.getIfAvailable());
    }

    private boolean infrastructureDeliberatelyExcluded() {
        String excludes = environment.getProperty("spring.autoconfigure.exclude", "");
        return excludes.contains("DataRedisAutoConfiguration") || excludes.contains("DataSourceAutoConfiguration");
    }

    private void requireResolved(String beanName, Object bean) {
        if (bean == null) {
            String message = beanName + " resolved to null at startup. Redis/DataSource "
                    + "autoconfiguration was not excluded, so this bean is expected to be "
                    + "available; refusing to start rather than risk a NullPointerException on "
                    + "first use.";
            log.error("auth bean availability guard refused to start: bean={}", beanName);
            throw new IllegalStateException(message);
        }
    }
}
