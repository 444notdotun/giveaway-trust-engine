package com.giveaway.giveawaytrustengine.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Slice 3 (Auth), Section 2 and "Tests summary".
 * Plan doc: docs/slices/03-auth.md, Section 2 ("Signing key: environment variable, no default,
 * minimum length enforced at startup") and "Tests summary" (the guard's own startup-refusal
 * tests, same CapturedOutput pattern as {@link StartupGuardTest}).
 *
 * {@code app.jwt.signing-key} is interpreted as BASE64, decoded to raw bytes, and the 32-byte
 * minimum is enforced on the DECODED byte length, never on the configured string's own length
 * -- the real key is {@code openssl rand -base64 48} output (64 base64 characters encoding 48
 * raw bytes). Every non-missing test value below is therefore itself base64-encoded.
 *
 * Mirrors {@link StartupGuardTest}'s own doc comment about never asserting only an in-memory
 * return value: every case here asserts the real startup failure (root cause type + message)
 * AND the real captured ERROR log line, never one without the other.
 */
@ExtendWith(OutputCaptureExtension.class)
class JwtSigningKeyGuardTest {

    private static final String GUARD_LOGGER = "JwtSigningKeyGuardBeanFactoryPostProcessor";

    private static ApplicationContextRunner guardedContext() {
        return new ApplicationContextRunner()
                .withBean(JwtSigningKeyGuardBeanFactoryPostProcessor.class);
    }

    private static String base64Of(int byteLength) {
        byte[] bytes = new byte[byteLength];
        for (int i = 0; i < byteLength; i++) {
            bytes[i] = (byte) i;
        }
        return Base64.getEncoder().encodeToString(bytes);
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

    private static void assertErrorLogLine(CapturedOutput output) {
        boolean found = output.getOut().lines()
                .anyMatch(line -> line.contains("ERROR") && line.contains(GUARD_LOGGER));
        assertThat(found)
                .as("expected one ERROR log line from " + GUARD_LOGGER + " but captured output was:\n"
                        + output.getOut())
                .isTrue();
    }

    // Case 1: app.jwt.signing-key missing entirely -- refuses to start. Unaffected by the base64
    // decode rule -- there is no value to decode.
    @Test
    void missingSigningKeyRefusesToStart(CapturedOutput output) {
        guardedContext()
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root.getMessage()).containsIgnoringCase("app.jwt.signing-key");
                    assertErrorLogLine(output);
                    // CLAUDE.md: never log or return the signing key -- nothing to leak here
                    // since the value is absent, but the message/log must still name the
                    // property, not dump whatever (empty) value was bound.
                });
    }

    // Case 2: app.jwt.signing-key present, valid base64, but decodes to well under 32 bytes.
    @Test
    void tooShortSigningKeyRefusesToStart(CapturedOutput output) {
        String tooShort = base64Of(18); // decodes to 18 bytes, well under 32
        guardedContext()
                .withPropertyValues("app.jwt.signing-key=" + tooShort)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root.getMessage()).containsIgnoringCase("app.jwt.signing-key");
                    assertErrorLogLine(output);
                    assertThat(output.getAll())
                            .as("the signing key value itself must never appear in logs, even when rejected")
                            .doesNotContain(tooShort);
                });
    }

    // Exact boundary, refused side: a base64 string that decodes to exactly 31 bytes is refused.
    @Test
    void base64DecodingToExactly31BytesRefusesToStart(CapturedOutput output) {
        String decodes31Bytes = base64Of(31);
        guardedContext()
                .withPropertyValues("app.jwt.signing-key=" + decodes31Bytes)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root.getMessage()).containsIgnoringCase("app.jwt.signing-key");
                    assertErrorLogLine(output);
                    assertThat(output.getAll())
                            .as("the signing key value itself must never appear in logs, even when rejected")
                            .doesNotContain(decodes31Bytes);
                });
    }

    // Exact boundary, accepted side: a base64 string that decodes to exactly 32 bytes starts
    // successfully.
    @Test
    void base64DecodingToExactly32BytesStarts(CapturedOutput output) {
        String decodes32Bytes = base64Of(32);
        guardedContext()
                .withPropertyValues("app.jwt.signing-key=" + decodes32Bytes)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(output.getAll())
                            .as("the signing key value itself must never appear in logs, even on success")
                            .doesNotContain(decodes32Bytes);
                });
    }

    // A configured value that isn't valid base64 at all must be refused outright, naming
    // app.jwt.signing-key -- never silently reinterpreted as raw UTF-8 bytes.
    @Test
    void nonBase64SigningKeyRefusesToStartWithoutFallingBackToRawUtf8(CapturedOutput output) {
        String notBase64 = "@@@@this-is-not-valid-base64@@@@";
        guardedContext()
                .withPropertyValues("app.jwt.signing-key=" + notBase64)
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root.getMessage()).containsIgnoringCase("app.jwt.signing-key");
                    assertErrorLogLine(output);
                    assertThat(output.getAll())
                            .as("the signing key value itself must never appear in logs, even when rejected")
                            .doesNotContain(notBase64);
                });
    }

    // Happy path: a signing key that base64-decodes to exactly 32 bytes starts successfully
    // (same case as base64DecodingToExactly32BytesStarts, kept under its original name too since
    // it was the pre-existing happy-path test).
    @Test
    void exactly32ByteDecodedSigningKeyStarts(CapturedOutput output) {
        String valid = base64Of(32);
        guardedContext()
                .withPropertyValues("app.jwt.signing-key=" + valid)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(output.getAll())
                            .as("the signing key value itself must never appear in logs, even on success")
                            .doesNotContain(valid);
                });
    }

    // Blank (whitespace-only) signing key must be treated as missing, not as a too-short value
    // that happens to pass some other check -- same whitespace discipline as StartupGuardTest.
    // Unaffected by the base64 decode rule -- isUnset() short-circuits before any decode attempt.
    @Test
    void whitespaceOnlySigningKeyRefusesToStart(CapturedOutput output) {
        guardedContext()
                .withInitializer(context -> context.getEnvironment().getPropertySources().addFirst(
                        new org.springframework.core.env.MapPropertySource("raw-test-value",
                                java.util.Map.of("app.jwt.signing-key", "   "))))
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable root = rootCause(context);
                    assertThat(root.getMessage()).containsIgnoringCase("app.jwt.signing-key");
                    assertErrorLogLine(output);
                });
    }
}
