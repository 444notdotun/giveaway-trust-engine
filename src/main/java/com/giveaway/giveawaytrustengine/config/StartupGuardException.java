package com.giveaway.giveawaytrustengine.config;

/**
 * Thrown by {@link StartupGuardBeanFactoryPostProcessor} when the configured environment and
 * Bachs mode don't match the required combination, or required config is missing/invalid.
 */
public class StartupGuardException extends RuntimeException {

    public StartupGuardException(String message) {
        super(message);
    }
}
