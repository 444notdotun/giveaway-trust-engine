package com.giveaway.giveawaytrustengine.quota;

import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;

/**
 * Wiring only (no business logic): makes {@link AccountQuotaService} available as a Spring bean,
 * with the real {@link MeterRegistry} this application already exposes -- same pattern as
 * {@code AuthBeansConfig} in the {@code auth} package.
 *
 * <p>Resolves its {@code DataSource} dependency via {@link ObjectProvider} and returns {@code
 * null} when it isn't available, for the identical reason {@code AuthBeansConfig}'s
 * DataSource-only beans ({@code communityManagerRepository}, {@code refreshTokenService}) do:
 * a handful of test contexts deliberately exclude {@code DataSourceAutoConfiguration} to boot a
 * DB-less application on purpose, and this must not prevent that. In the real application, a
 * {@code null} here is caught at startup by {@code AuthBeanAvailabilityGuard}, not silently
 * passed through to the first caller.
 */
@Configuration
public class QuotaBeansConfig {

    @Bean
    public AccountQuotaService accountQuotaService(ObjectProvider<DataSource> dataSource, MeterRegistry meterRegistry) {
        DataSource source = dataSource.getIfAvailable();
        if (source == null) {
            return null;
        }
        return new AccountQuotaService(source, meterRegistry);
    }
}
