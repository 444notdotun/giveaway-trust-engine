package com.giveaway.giveawaytrustengine.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.EnvironmentAware;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.stereotype.Component;

/**
 * Refuses to start the application if the configured {@code app.environment} and the Bachs
 * base URL in effect ({@code app.bachs.base-url}) don't match the required combination:
 * DEV/STAGING must be sandbox, PRODUCTION must be live. See
 * docs/slices/02-startup-guard-and-typed-config.md for the full design and the reasoning for
 * why this runs as a {@link BeanFactoryPostProcessor} rather than an ordinary bean.
 *
 * Plain {@code @Component} (not a {@code static @Bean} factory method) so component scanning
 * picks it up directly -- no risk of the well-known "non-static @Bean factory method for a
 * BeanFactoryPostProcessor runs too late" pitfall.
 */
@Component
public class StartupGuardBeanFactoryPostProcessor implements BeanFactoryPostProcessor, EnvironmentAware {

    private static final Logger log = LoggerFactory.getLogger(StartupGuardBeanFactoryPostProcessor.class);

    private ConfigurableEnvironment environment;

    @Override
    public void setEnvironment(org.springframework.core.env.Environment environment) {
        this.environment = (ConfigurableEnvironment) environment;
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        Binder binder = Binder.get(environment);

        String envRaw = binder.bind("app.environment", String.class).orElse(null);
        if (isUnset(envRaw)) {
            throw fail("app.environment is required");
        }
        Environment env;
        try {
            env = Environment.valueOf(envRaw);
        }
        catch (IllegalArgumentException ex) {
            throw fail("app.environment '" + envRaw + "' is not one of DEV, STAGING, or PRODUCTION");
        }

        String sandboxUrl = binder.bind("app.bachs.sandbox-base-url", String.class).orElse(null);
        if (isUnset(sandboxUrl)) {
            throw fail("app.bachs.sandbox-base-url is required");
        }

        String liveUrl = binder.bind("app.bachs.live-base-url", String.class).orElse(null);
        if (isUnset(liveUrl)) {
            throw fail("app.bachs.live-base-url is required");
        }

        String configured = binder.bind("app.bachs.base-url", String.class).orElse(null);
        if (isUnset(configured)) {
            throw fail("app.bachs.base-url is required");
        }

        if (sandboxUrl.equals(liveUrl)) {
            throw fail("app.bachs.sandbox-base-url and app.bachs.live-base-url must not be the same value");
        }

        BachsMode mode;
        if (configured.equals(sandboxUrl)) {
            mode = BachsMode.SANDBOX;
        }
        else if (configured.equals(liveUrl)) {
            mode = BachsMode.LIVE;
        }
        else {
            throw fail("app.bachs.base-url does not exactly match the configured sandbox or live URL");
        }

        boolean allowed = switch (env) {
            case DEV, STAGING -> mode == BachsMode.SANDBOX;
            case PRODUCTION -> mode == BachsMode.LIVE;
        };
        if (!allowed) {
            throw fail(env + " must not run with Bachs in " + mode + " mode");
        }

        log.info("startup guard passed: environment={} bachsMode={}", env, mode);
    }

    private StartupGuardException fail(String message) {
        log.error("startup guard refused to start: {}", message);
        return new StartupGuardException(message);
    }

    /**
     * True for null, blank, or any value still containing an unresolved {@code ${...}}
     * placeholder fragment -- whether the whole value is a bare placeholder (a forgotten env
     * var, e.g. {@code app.environment=${APP_ENVIRONMENT}} with APP_ENVIRONMENT never exported)
     * or the placeholder is only part of the value (e.g. {@code https://${HOST}.example.test}).
     * Either way this must be treated the same as "missing", not passed on to enum parsing or
     * URL comparison where it would leak into an unrelated error message.
     */
    private static boolean isUnset(String value) {
        return value == null || value.isBlank() || value.contains("${");
    }

    private enum BachsMode {
        SANDBOX,
        LIVE
    }
}
