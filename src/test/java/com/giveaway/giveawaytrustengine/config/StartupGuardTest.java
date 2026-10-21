package com.giveaway.giveawaytrustengine.config;

import com.giveaway.giveawaytrustengine.GiveawayTrustEngineApplication;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.util.Arrays;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Slice 2: Startup guard and typed config.
 * Plan doc: docs/slices/02-startup-guard-and-typed-config.md ("Failure cases" + "Tests" sections).
 *
 * All "logic tests" below use {@link ApplicationContextRunner} in total isolation (no DataSource,
 * no Redis, no Testcontainers) and register only {@code StartupGuardBeanFactoryPostProcessor},
 * with fake test URLs (https://sandbox.example.test, https://live.example.test) per the plan's
 * decision that the guard's own unit tests must stay decoupled from the real Bachs domain.
 *
 * Every refusal test asserts a single ERROR log line, from this guard's own logger, naming the
 * specific property or environment/mode detail -- via {@link #assertErrorLogLine}, not a loose
 * "output contains ERROR somewhere AND contains the property somewhere, possibly on different
 * lines" check. Verified by mutation: deleting the log.error(...) call in the guard's fail()
 * helper (keeping the throw) turns every one of these tests red, proving none of them is
 * decorative.
 */
@ExtendWith(OutputCaptureExtension.class)
class StartupGuardTest {

    private static final String FAKE_SANDBOX_URL = "https://sandbox.example.test";
    private static final String FAKE_LIVE_URL = "https://live.example.test";
    private static final String GUARD_LOGGER = "StartupGuardBeanFactoryPostProcessor";

    private static ApplicationContextRunner guardedContext() {
        return new ApplicationContextRunner()
                .withBean(StartupGuardBeanFactoryPostProcessor.class);
    }

    /**
     * Adds one property with its value preserved exactly as given -- {@code withPropertyValues}
     * parses "key=value" strings via {@code TestPropertyValues.Pair.parse}, which calls
     * {@code value.trim()}, so a literal "   " passed to {@code withPropertyValues} silently
     * becomes "" before the guard ever sees it. A whitespace-only test needs this instead, to
     * actually exercise the whitespace case rather than accidentally duplicating the blank case.
     */
    private static ApplicationContextRunner guardedContextWithRawProperty(String key, String rawValue) {
        return guardedContext().withInitializer(context -> {
            ConfigurableEnvironment environment = context.getEnvironment();
            environment.getPropertySources()
                    .addFirst(new MapPropertySource("raw-test-value", Map.of(key, rawValue)));
        });
    }

    private static Throwable rootCause(AssertableApplicationContext context) {
        Throwable failure = context.getStartupFailure();
        assertThat(failure).as("expected a startup failure but context did not fail").isNotNull();
        Throwable cursor = failure;
        while (cursor.getCause() != null) {
            cursor = cursor.getCause();
        }
        return cursor;
    }

    /**
     * Asserts a single captured output line contains "ERROR", this guard's own logger name, and
     * every one of {@code mustContainAll} -- tighter than checking each fragment independently
     * across the whole output, which could match "ERROR" on one unrelated line and the property
     * name on another.
     */
    private static void assertErrorLogLine(CapturedOutput output, String... mustContainAll) {
        boolean found = output.getOut().lines().anyMatch(line ->
                line.contains("ERROR")
                        && line.contains(GUARD_LOGGER)
                        && Arrays.stream(mustContainAll).allMatch(line::contains));
        assertThat(found)
                .as("expected one ERROR log line from " + GUARD_LOGGER + " containing all of "
                        + Arrays.toString(mustContainAll) + " but captured output was:\n" + output.getOut())
                .isTrue();
    }

    // Case 1: dev + sandbox -- starts. Happy path, one of the four BUILD_ORDER-required tests.
    @Test
    void devWithSandboxUrlStarts(CapturedOutput output) {
        guardedContext()
                .withPropertyValues(
                        "app.environment=DEV",
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL,
                        "app.bachs.base-url=" + FAKE_SANDBOX_URL)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(output.getOut()).contains("INFO").contains("DEV").contains("SANDBOX");
                    assertThat(output.getAll()).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 2: staging + live -- refuses (environment/mode mismatch).
    @Test
    void stagingWithLiveUrlRefuses(CapturedOutput output) {
        guardedContext()
                .withPropertyValues(
                        "app.environment=STAGING",
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL,
                        "app.bachs.base-url=" + FAKE_LIVE_URL)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage()).contains("STAGING").containsIgnoringCase("live");
                    assertErrorLogLine(output, "STAGING");
                    assertThat(output.getAll()).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 3: production + sandbox -- refuses (environment/mode mismatch).
    @Test
    void productionWithSandboxUrlRefuses(CapturedOutput output) {
        guardedContext()
                .withPropertyValues(
                        "app.environment=PRODUCTION",
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL,
                        "app.bachs.base-url=" + FAKE_SANDBOX_URL)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage()).contains("PRODUCTION").containsIgnoringCase("sandbox");
                    assertErrorLogLine(output, "PRODUCTION");
                    assertThat(output.getAll()).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 4: production + live -- starts. Happy path, one of the four BUILD_ORDER-required tests.
    @Test
    void productionWithLiveUrlStarts(CapturedOutput output) {
        guardedContext()
                .withPropertyValues(
                        "app.environment=PRODUCTION",
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL,
                        "app.bachs.base-url=" + FAKE_LIVE_URL)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(output.getOut()).contains("INFO").contains("PRODUCTION").contains("LIVE");
                    assertThat(output.getAll()).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 5: dev + live -- refuses (rule's logical consequence; dev must never talk to real payment infra).
    @Test
    void devWithLiveUrlRefuses(CapturedOutput output) {
        guardedContext()
                .withPropertyValues(
                        "app.environment=DEV",
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL,
                        "app.bachs.base-url=" + FAKE_LIVE_URL)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage()).contains("DEV").containsIgnoringCase("live");
                    assertErrorLogLine(output, "DEV");
                    assertThat(output.getAll()).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 6a: base-url is a typo / entirely different value -- refuses, message names app.bachs.base-url.
    @Test
    void unrecognizedBaseUrlTypoRefuses(CapturedOutput output) {
        String typo = "https://totally-different.example.test";
        guardedContext()
                .withPropertyValues(
                        "app.environment=DEV",
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL,
                        "app.bachs.base-url=" + typo)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage()).contains("app.bachs.base-url");
                    assertErrorLogLine(output, "app.bachs.base-url");
                    assertThat(output.getAll()).doesNotContain(typo).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 6b: base-url is the real sandbox URL plus a trailing slash -- refuses, proves exact-match not substring.
    @Test
    void unrecognizedBaseUrlTrailingSlashRefuses(CapturedOutput output) {
        String trailingSlash = FAKE_SANDBOX_URL + "/";
        guardedContext()
                .withPropertyValues(
                        "app.environment=DEV",
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL,
                        "app.bachs.base-url=" + trailingSlash)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage()).contains("app.bachs.base-url");
                    assertErrorLogLine(output, "app.bachs.base-url");
                    assertThat(output.getAll()).doesNotContain(trailingSlash).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 6c: base-url is the real sandbox URL in different case -- refuses, proves exact-match not case-insensitive.
    @Test
    void unrecognizedBaseUrlDifferentCaseRefuses(CapturedOutput output) {
        String differentCase = "https://SANDBOX.example.test";
        guardedContext()
                .withPropertyValues(
                        "app.environment=DEV",
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL,
                        "app.bachs.base-url=" + differentCase)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage()).contains("app.bachs.base-url");
                    assertErrorLogLine(output, "app.bachs.base-url");
                    assertThat(output.getAll()).doesNotContain(differentCase).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 6d: base-url is an exact prefix of the real sandbox URL -- refuses, proves exact-match not prefix.
    @Test
    void unrecognizedBaseUrlPrefixRefuses(CapturedOutput output) {
        String prefix = "https://sandbox.example.te";
        guardedContext()
                .withPropertyValues(
                        "app.environment=DEV",
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL,
                        "app.bachs.base-url=" + prefix)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage()).contains("app.bachs.base-url");
                    assertErrorLogLine(output, "app.bachs.base-url");
                    assertThat(output.getAll()).doesNotContain(prefix).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 7 (DEV): sandbox URL equals live URL -- refuses regardless of environment.
    @Test
    void sandboxEqualsLiveUrlRefusesInDev(CapturedOutput output) {
        String sameUrl = "https://same.example.test";
        guardedContext()
                .withPropertyValues(
                        "app.environment=DEV",
                        "app.bachs.sandbox-base-url=" + sameUrl,
                        "app.bachs.live-base-url=" + sameUrl,
                        "app.bachs.base-url=" + sameUrl)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage()).contains("app.bachs.sandbox-base-url").contains("app.bachs.live-base-url");
                    assertErrorLogLine(output, "app.bachs.sandbox-base-url", "app.bachs.live-base-url");
                    assertThat(output.getAll()).doesNotContain(sameUrl);
                });
    }

    // Case 7 (STAGING): sandbox URL equals live URL -- refuses regardless of environment.
    @Test
    void sandboxEqualsLiveUrlRefusesInStaging(CapturedOutput output) {
        String sameUrl = "https://same.example.test";
        guardedContext()
                .withPropertyValues(
                        "app.environment=STAGING",
                        "app.bachs.sandbox-base-url=" + sameUrl,
                        "app.bachs.live-base-url=" + sameUrl,
                        "app.bachs.base-url=" + sameUrl)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage()).contains("app.bachs.sandbox-base-url").contains("app.bachs.live-base-url");
                    assertErrorLogLine(output, "app.bachs.sandbox-base-url", "app.bachs.live-base-url");
                    assertThat(output.getAll()).doesNotContain(sameUrl);
                });
    }

    // Case 7 (PRODUCTION): sandbox URL equals live URL -- refuses regardless of environment.
    @Test
    void sandboxEqualsLiveUrlRefusesInProduction(CapturedOutput output) {
        String sameUrl = "https://same.example.test";
        guardedContext()
                .withPropertyValues(
                        "app.environment=PRODUCTION",
                        "app.bachs.sandbox-base-url=" + sameUrl,
                        "app.bachs.live-base-url=" + sameUrl,
                        "app.bachs.base-url=" + sameUrl)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage()).contains("app.bachs.sandbox-base-url").contains("app.bachs.live-base-url");
                    assertErrorLogLine(output, "app.bachs.sandbox-base-url", "app.bachs.live-base-url");
                    assertThat(output.getAll()).doesNotContain(sameUrl);
                });
    }

    // Case 8a: app.bachs.sandbox-base-url blank -- refuses, message names the property.
    @Test
    void blankSandboxBaseUrlRefuses(CapturedOutput output) {
        guardedContext()
                .withPropertyValues(
                        "app.environment=DEV",
                        "app.bachs.sandbox-base-url=",
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL,
                        "app.bachs.base-url=" + FAKE_SANDBOX_URL)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage()).contains("app.bachs.sandbox-base-url");
                    assertErrorLogLine(output, "app.bachs.sandbox-base-url");
                    assertThat(output.getAll()).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 8a-whitespace: app.bachs.sandbox-base-url is whitespace-only -- refuses, same as blank.
    @Test
    void whitespaceOnlySandboxBaseUrlRefuses(CapturedOutput output) {
        guardedContextWithRawProperty("app.bachs.sandbox-base-url", "   ")
                .withPropertyValues(
                        "app.environment=DEV",
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL,
                        "app.bachs.base-url=" + FAKE_SANDBOX_URL)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage()).contains("app.bachs.sandbox-base-url");
                    assertErrorLogLine(output, "app.bachs.sandbox-base-url");
                    assertThat(output.getAll()).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 8b: app.bachs.live-base-url blank -- refuses, message names the property.
    @Test
    void blankLiveBaseUrlRefuses(CapturedOutput output) {
        guardedContext()
                .withPropertyValues(
                        "app.environment=DEV",
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.live-base-url=",
                        "app.bachs.base-url=" + FAKE_SANDBOX_URL)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage()).contains("app.bachs.live-base-url");
                    assertErrorLogLine(output, "app.bachs.live-base-url");
                    assertThat(output.getAll()).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 8b-whitespace: app.bachs.live-base-url is whitespace-only -- refuses, same as blank.
    @Test
    void whitespaceOnlyLiveBaseUrlRefuses(CapturedOutput output) {
        guardedContextWithRawProperty("app.bachs.live-base-url", "   ")
                .withPropertyValues(
                        "app.environment=DEV",
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.base-url=" + FAKE_SANDBOX_URL)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage()).contains("app.bachs.live-base-url");
                    assertErrorLogLine(output, "app.bachs.live-base-url");
                    assertThat(output.getAll()).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 8c: app.bachs.base-url blank -- refuses, message names the property.
    @Test
    void blankConfiguredBaseUrlRefuses(CapturedOutput output) {
        guardedContext()
                .withPropertyValues(
                        "app.environment=DEV",
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL,
                        "app.bachs.base-url=")
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage()).contains("app.bachs.base-url");
                    assertErrorLogLine(output, "app.bachs.base-url");
                    assertThat(output.getAll()).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 8c-whitespace: app.bachs.base-url is whitespace-only -- refuses, same as blank.
    @Test
    void whitespaceOnlyConfiguredBaseUrlRefuses(CapturedOutput output) {
        guardedContextWithRawProperty("app.bachs.base-url", "   ")
                .withPropertyValues(
                        "app.environment=DEV",
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage())
                            .as("must be treated as unset, not fall through to the mismatch check")
                            .isEqualTo("app.bachs.base-url is required");
                    assertErrorLogLine(output, "app.bachs.base-url");
                    assertThat(output.getAll()).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 8d: app.environment missing entirely -- refuses, message names app.environment.
    @Test
    void missingEnvironmentRefuses(CapturedOutput output) {
        guardedContext()
                .withPropertyValues(
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL,
                        "app.bachs.base-url=" + FAKE_SANDBOX_URL)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage()).contains("app.environment");
                    assertErrorLogLine(output, "app.environment");
                    assertThat(output.getAll()).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 8d-whitespace: app.environment is whitespace-only -- refuses, same as missing.
    @Test
    void whitespaceOnlyEnvironmentRefuses(CapturedOutput output) {
        guardedContextWithRawProperty("app.environment", "   ")
                .withPropertyValues(
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL,
                        "app.bachs.base-url=" + FAKE_SANDBOX_URL)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage())
                            .as("must be treated as unset, not fall through to enum-parse-failure")
                            .isEqualTo("app.environment is required");
                    assertErrorLogLine(output, "app.environment");
                    assertThat(output.getAll()).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 8f: app.environment resolves to a literal unresolved ${...} placeholder -- the shape
    // a forgotten env var takes on Render (application.properties has app.environment=${APP_ENVIRONMENT}
    // with no default; APP_ENVIRONMENT never exported). Must be treated as missing, with a message
    // naming the property, not the raw placeholder or a binding stack trace.
    @Test
    void unresolvedPlaceholderEnvironmentRefusesWithClearMessage(CapturedOutput output) {
        guardedContext()
                .withPropertyValues(
                        "app.environment=${SOME_ENV_VAR_THAT_IS_DEFINITELY_NOT_SET_12345}",
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL,
                        "app.bachs.base-url=" + FAKE_SANDBOX_URL)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage())
                            .isEqualTo("app.environment is required")
                            .as("must not leak the raw unresolved placeholder into the message")
                            .doesNotContain("${");
                    assertErrorLogLine(output, "app.environment");
                    assertThat(output.getAll())
                            .doesNotContain("${")
                            .doesNotContain(FAKE_SANDBOX_URL)
                            .doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Partial placeholder: app.bachs.base-url is only PART of an unresolved placeholder
    // (https://${UNSET_HOST}.example.test), not the whole value. Must still be treated as
    // missing, same as a bare placeholder -- proves isUnset() checks for the "${" fragment
    // anywhere in the value, not only a full-value regex match.
    @Test
    void partialPlaceholderBaseUrlRefusesWithClearMessage(CapturedOutput output) {
        guardedContext()
                .withPropertyValues(
                        "app.environment=DEV",
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL,
                        "app.bachs.base-url=https://${UNSET_HOST_FOR_TEST}.example.test")
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage())
                            .isEqualTo("app.bachs.base-url is required")
                            .doesNotContain("${");
                    assertErrorLogLine(output, "app.bachs.base-url");
                    assertThat(output.getAll())
                            .doesNotContain("${")
                            .doesNotContain(FAKE_SANDBOX_URL)
                            .doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 8e: app.environment set to an invalid value (PROD) -- refuses, message names app.environment and the bad value.
    @Test
    void invalidEnvironmentValueRefuses(CapturedOutput output) {
        guardedContext()
                .withPropertyValues(
                        "app.environment=PROD",
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL,
                        "app.bachs.base-url=" + FAKE_SANDBOX_URL)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage()).contains("app.environment").contains("PROD");
                    assertErrorLogLine(output, "app.environment");
                    assertThat(output.getAll()).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Case 8g: app.environment is case-sensitive -- lowercase "dev" is refused, not silently
    // uppercased. Matches BUILD_ORDER's "exact comparison, never substring/loose-match" ethos
    // extended to the environment value itself, not just the Bachs URLs.
    @Test
    void lowercaseEnvironmentValueRefuses(CapturedOutput output) {
        guardedContext()
                .withPropertyValues(
                        "app.environment=dev",
                        "app.bachs.sandbox-base-url=" + FAKE_SANDBOX_URL,
                        "app.bachs.live-base-url=" + FAKE_LIVE_URL,
                        "app.bachs.base-url=" + FAKE_SANDBOX_URL)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root).isInstanceOf(StartupGuardException.class);
                    assertThat(root.getMessage()).contains("app.environment").contains("dev");
                    assertErrorLogLine(output, "app.environment");
                    assertThat(output.getAll()).doesNotContain(FAKE_SANDBOX_URL).doesNotContain(FAKE_LIVE_URL);
                });
    }

    // Real app wiring, bad combination: STAGING + the real live URL fails to start with
    // StartupGuardException as the ROOT CAUSE, with NO DataSource/Flyway/Redis autoconfiguration
    // excluded and no database available anywhere. This is the test that actually proves the
    // guard runs before any other bean -- including the DataSource -- is ever created: if it
    // didn't, this test would fail for the wrong reason (a Hikari/Flyway connection failure)
    // instead of StartupGuardException.
    @Test
    void realApplicationRefusesToStartWithStagingAndRealLiveUrl() {
        SpringApplicationBuilder builder = new SpringApplicationBuilder(GiveawayTrustEngineApplication.class)
                .web(WebApplicationType.NONE);

        try {
            // Command-line args, not .properties(...): SpringApplicationBuilder.properties(...)
            // adds DEFAULT properties, which are lower priority than application.properties'
            // ${APP_ENVIRONMENT} placeholders -- command-line args are the highest-precedence
            // source, so this is the only reliable way to override them from a test.
            ConfigurableApplicationContext context = builder.run(
                    "--app.environment=STAGING",
                    "--app.bachs.sandbox-base-url=https://sandbox-api.bachs.io",
                    "--app.bachs.live-base-url=https://api.bachs.io",
                    "--app.bachs.base-url=https://api.bachs.io");
            context.close();
            fail("expected the real application to fail to start for STAGING + live base-url");
        } catch (Exception startupFailure) {
            Throwable cursor = startupFailure;
            while (cursor.getCause() != null) {
                cursor = cursor.getCause();
            }
            assertThat(cursor).isInstanceOf(StartupGuardException.class);
            assertThat(cursor.getMessage()).contains("STAGING").containsIgnoringCase("live");
        }
    }

    // Real app wiring, valid combination: DEV + the real sandbox URL starts successfully with
    // DataSource/Flyway/Redis autoconfiguration excluded (no real Postgres/Redis available in
    // this test run, and the point here is only to prove the valid path gets past the guard in
    // the real, actually-wired application -- unlike the bad-combination test above, this one
    // does need to actually finish starting, so the exclusions stay here).
    @Test
    void realApplicationStartsWithDevAndRealSandboxUrl() {
        SpringApplicationBuilder builder = new SpringApplicationBuilder(GiveawayTrustEngineApplication.class)
                .web(WebApplicationType.NONE);

        ConfigurableApplicationContext context = builder.run(
                "--spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,"
                        + "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration,"
                        + "org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration",
                "--app.environment=DEV",
                "--app.bachs.sandbox-base-url=https://sandbox-api.bachs.io",
                "--app.bachs.live-base-url=https://api.bachs.io",
                "--app.bachs.base-url=https://sandbox-api.bachs.io");
        try {
            assertThat(context.isActive()).isTrue();
        } finally {
            context.close();
        }
    }
}
