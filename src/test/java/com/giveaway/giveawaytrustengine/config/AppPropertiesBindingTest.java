package com.giveaway.giveawaytrustengine.config;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Slice 2: Startup guard and typed config.
 * Plan doc: docs/slices/02-startup-guard-and-typed-config.md, "AppProperties binding test, and
 * the deviation from CLAUDE.md" section -- the 19th (per this plan's own count) test proving
 * AppProperties itself binds correctly through normal @ConfigurationProperties mechanics,
 * independent of the guard's own hand-rolled Binder usage.
 */
class AppPropertiesBindingTest {

    @Configuration
    @EnableConfigurationProperties(AppProperties.class)
    static class BindingTestConfig {
    }

    @Test
    void appPropertiesBindsEnvironmentAndAllThreeBachsFields() {
        new ApplicationContextRunner()
                .withConfiguration(org.springframework.boot.autoconfigure.AutoConfigurations.of(
                        ConfigurationPropertiesAutoConfiguration.class))
                .withUserConfiguration(BindingTestConfig.class)
                .withPropertyValues(
                        "app.environment=DEV",
                        "app.bachs.sandbox-base-url=https://sandbox.example.test",
                        "app.bachs.live-base-url=https://live.example.test",
                        "app.bachs.base-url=https://sandbox.example.test")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    AppProperties properties = context.getBean(AppProperties.class);
                    assertThat(properties.environment()).isEqualTo(Environment.DEV);
                    assertThat(properties.bachs().sandboxBaseUrl()).isEqualTo("https://sandbox.example.test");
                    assertThat(properties.bachs().liveBaseUrl()).isEqualTo("https://live.example.test");
                    assertThat(properties.bachs().baseUrl()).isEqualTo("https://sandbox.example.test");
                });
    }
}
