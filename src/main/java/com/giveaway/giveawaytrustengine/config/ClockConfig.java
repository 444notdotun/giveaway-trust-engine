package com.giveaway.giveawaytrustengine.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * CLAUDE.md: "Time comes from an injected Clock. Never call Instant.now() in business code."
 * One real system clock bean, injected everywhere a Clock is needed.
 */
@Configuration
public class ClockConfig {

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }
}
