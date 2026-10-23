package com.giveaway.giveawaytrustengine.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;

/**
 * Typed shape for {@code app.revocation.*} config. See docs/slices/03-auth.md, Section 4a.
 *
 * {@code epochTtl} defaults to 24 hours -- deliberately generous relative to the 15-minute
 * access-token lifetime, so the revocation-epoch marker only ever lapses during a genuinely idle
 * stretch with no revocation checks at all for a full day, by which point any token that could
 * still have been "live" has already expired on its own. {@code RevocationChecker}'s own
 * constructor independently validates this is at least twice the access-token lifetime,
 * regardless of what's configured here.
 */
@ConfigurationProperties(prefix = "app.revocation")
public record RevocationProperties(@DefaultValue("24h") Duration epochTtl) {
}
