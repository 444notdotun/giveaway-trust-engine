package com.giveaway.giveawaytrustengine.config;

/**
 * Thrown by {@link JwtSigningKeyGuardBeanFactoryPostProcessor} when {@code app.jwt.signing-key}
 * is missing/blank, not valid base64, or decodes to fewer than 32 bytes.
 */
public class JwtSigningKeyGuardException extends RuntimeException {

    public JwtSigningKeyGuardException(String message) {
        super(message);
    }
}
