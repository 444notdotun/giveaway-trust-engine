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

import java.util.Base64;

/**
 * Refuses to start the application if {@code app.jwt.signing-key} is missing/blank, is not
 * valid base64, or decodes to fewer than 32 raw bytes. The real key is produced with
 * {@code openssl rand -base64 48} (64 base64 characters encoding 48 raw bytes); the minimum is
 * enforced on the DECODED byte length, never on the length of the configured base64 string
 * itself. See docs/slices/03-auth.md, Section 2.
 *
 * Mirrors {@link StartupGuardBeanFactoryPostProcessor} exactly: a plain {@code @Component}
 * {@link BeanFactoryPostProcessor} + {@link EnvironmentAware}, not a {@code static @Bean}
 * factory method, for the same "runs too late" reason documented there.
 */
@Component
public class JwtSigningKeyGuardBeanFactoryPostProcessor implements BeanFactoryPostProcessor, EnvironmentAware {

    private static final Logger log = LoggerFactory.getLogger(JwtSigningKeyGuardBeanFactoryPostProcessor.class);

    private static final int MIN_DECODED_BYTES = 32;

    private ConfigurableEnvironment environment;

    @Override
    public void setEnvironment(org.springframework.core.env.Environment environment) {
        this.environment = (ConfigurableEnvironment) environment;
    }

    @Override
    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        Binder binder = Binder.get(environment);

        String raw = binder.bind("app.jwt.signing-key", String.class).orElse(null);
        if (isUnset(raw)) {
            throw fail("app.jwt.signing-key is required");
        }

        byte[] decoded;
        try {
            decoded = Base64.getDecoder().decode(raw);
        }
        catch (IllegalArgumentException ex) {
            // Never fall back to treating the value as raw UTF-8 -- a malformed base64 value is
            // refused outright, not silently reinterpreted.
            throw fail("app.jwt.signing-key is not valid base64");
        }

        if (decoded.length < MIN_DECODED_BYTES) {
            throw fail("app.jwt.signing-key must decode to at least " + MIN_DECODED_BYTES + " bytes");
        }

        log.info("jwt signing key guard passed: decodedByteLength={}", decoded.length);
    }

    private JwtSigningKeyGuardException fail(String message) {
        log.error("jwt signing key guard refused to start: {}", message);
        return new JwtSigningKeyGuardException(message);
    }

    /**
     * Same discipline as {@link StartupGuardBeanFactoryPostProcessor#isUnset(String)}: null,
     * blank, or an unresolved {@code ${...}} placeholder fragment are all treated as missing.
     */
    private static boolean isUnset(String value) {
        return value == null || value.isBlank() || value.contains("${");
    }
}
