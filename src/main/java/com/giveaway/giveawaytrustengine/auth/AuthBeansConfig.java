package com.giveaway.giveawaytrustengine.auth;

import com.giveaway.giveawaytrustengine.config.JwtProperties;
import com.giveaway.giveawaytrustengine.config.XOAuthProperties;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

import javax.sql.DataSource;
import java.time.Clock;
import java.time.Duration;

/**
 * Wiring only (no business logic): makes {@link JwtService} and {@link RevocationChecker}
 * available as Spring beans so {@link JwtAuthenticationFilter} (registered as a real servlet
 * filter) and {@link ResolvePingController} can be autowired with them. See
 * docs/slices/03-auth.md, Section 2 (tokens) and Section 4 (revocation).
 *
 * The 15-minute revoked-key TTL matches the access-token lifetime (Section 2/4) -- not an
 * independently chosen value.
 *
 * {@code revocationChecker} resolves its {@code LettuceConnectionFactory} dependency via
 * {@link ObjectProvider} rather than a direct parameter, and returns {@code null} when the
 * factory isn't available -- deliberately NOT {@code @ConditionalOnBean}, which evaluates
 * against bean DEFINITIONS during configuration-class processing and is ordering-sensitive
 * relative to {@code DataRedisAutoConfiguration}'s own deferred import (observed directly: it
 * incorrectly treated the auto-configured factory as absent in a real booted app even when Redis
 * was genuinely configured and reachable). {@code ObjectProvider.getIfAvailable()} is resolved
 * lazily at actual bean-instantiation time, by which point every bean definition (regardless of
 * processing order) is already registered -- so contexts that deliberately exclude Redis
 * autoconfiguration (e.g. {@code StartupGuardTest}, {@code StructuredLoggingIntegrationTest} --
 * neither of which needs this slice's auth wiring, or ever calls {@link ResolvePingController})
 * still boot fine with a {@code null} checker, while contexts with a real, reachable Redis get a
 * real one reliably.
 */
@Configuration
public class AuthBeansConfig {

    @Bean
    public JwtService jwtService(JwtProperties jwtProperties, Clock clock) {
        return new JwtService(jwtProperties.signingKey(), clock);
    }

    @Bean
    public RevocationChecker revocationChecker(ObjectProvider<LettuceConnectionFactory> connectionFactory,
            ObjectProvider<DataSource> dataSource, Clock clock, MeterRegistry meterRegistry) {
        LettuceConnectionFactory factory = connectionFactory.getIfAvailable();
        DataSource source = dataSource.getIfAvailable();
        if (factory == null || source == null) {
            return null;
        }
        return new RevocationChecker(source, factory, clock, Duration.ofMinutes(15), meterRegistry);
    }

    /**
     * Returns {@code null} in contexts without Redis autoconfiguration (same {@code
     * ObjectProvider}-resolved-lazily reasoning as {@link #revocationChecker} above) --
     * {@link OAuthLoginController} takes this via {@code ObjectProvider} for the same reason
     * {@link ResolvePingController} takes {@link RevocationChecker} that way.
     */
    @Bean
    public OAuthStateService oauthStateService(ObjectProvider<LettuceConnectionFactory> connectionFactory) {
        LettuceConnectionFactory factory = connectionFactory.getIfAvailable();
        if (factory == null) {
            return null;
        }
        return new OAuthStateService(factory, Duration.ofMinutes(5));
    }

    @Bean
    public XOAuthClient xOAuthClient(XOAuthProperties oAuthProperties) {
        return new XOAuthClient(oAuthProperties);
    }

    /** Returns {@code null} in contexts without a real {@code DataSource} -- same reasoning as above. */
    @Bean
    public CommunityManagerRepository communityManagerRepository(ObjectProvider<DataSource> dataSource, Clock clock) {
        DataSource source = dataSource.getIfAvailable();
        if (source == null) {
            return null;
        }
        return new CommunityManagerRepository(source, clock);
    }

    /** Returns {@code null} in contexts without a real {@code DataSource} -- same reasoning as above. */
    @Bean
    public RefreshTokenService refreshTokenService(ObjectProvider<DataSource> dataSource, Clock clock,
            ObjectProvider<RevocationChecker> revocationChecker, JwtService jwtService, MeterRegistry meterRegistry) {
        DataSource source = dataSource.getIfAvailable();
        if (source == null) {
            return null;
        }
        return new RefreshTokenService(source, clock, revocationChecker.getIfAvailable(), jwtService, meterRegistry);
    }
}
