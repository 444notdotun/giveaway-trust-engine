package com.giveaway.giveawaytrustengine.logging;

import com.giveaway.giveawaytrustengine.GiveawayTrustEngineApplication;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.ConfigurableApplicationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Slice 2b: Structured logging.
 * Plan doc: docs/slices/02b-structured-logging.md, Section 1 (structured JSON console output)
 * and Section 5 (failure tests 6 and 7 -- the two real-application, actual-JSON-parser tests).
 * PRD Section 14 (Observability).
 *
 * Boots the real {@code GiveawayTrustEngineApplication} (no DataSource/Flyway/Redis available in
 * this test run -- same autoconfiguration exclusions already used by
 * {@code StartupGuardTest#realApplicationStartsWithDevAndRealSandboxUrl}), with
 * {@code logging.structured.format.console=ecs} passed as a real Spring property (command-line
 * argument, not a hand-built ApplicationContextRunner that bypasses the application's actual
 * property binding), and parses captured stdout with an actual JSON library -- never substring
 * matching -- per the plan doc's explicit instruction for these two tests.
 */
@ExtendWith(OutputCaptureExtension.class)
class StructuredLoggingIntegrationTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    private static SpringApplicationBuilder realAppBuilder() {
        return new SpringApplicationBuilder(GiveawayTrustEngineApplication.class)
                .web(WebApplicationType.SERVLET);
    }

    private static String[] realAppArgs(String... extra) {
        List<String> args = new java.util.ArrayList<>(List.of(
                "--spring.autoconfigure.exclude=org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration,"
                        + "org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration,"
                        + "org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration",
                "--app.environment=DEV",
                "--app.bachs.sandbox-base-url=https://sandbox-api.bachs.io",
                "--app.bachs.live-base-url=https://api.bachs.io",
                "--app.bachs.base-url=https://sandbox-api.bachs.io",
                "--server.port=0",
                "--logging.structured.format.console=ecs"));
        args.addAll(List.of(extra));
        return args.toArray(new String[0]);
    }

    /**
     * Parses every line of captured stdout that is valid JSON, skipping anything that isn't
     * (plain non-JSON noise, blank lines, etc.) -- never a substring check.
     */
    private static List<JsonNode> parseAllJsonLines(CapturedOutput output) {
        return output.getOut().lines()
                .filter(line -> !line.isBlank())
                .map(line -> {
                    try {
                        return JSON.readTree(line);
                    } catch (Exception notJson) {
                        return null;
                    }
                })
                .filter(node -> node != null && node.isObject())
                .toList();
    }

    // Happy path (Tests summary): logging.structured.format.console=ecs actually produces
    // parseable JSON for a sample log line -- parsed with a real JSON library, not eyeballed.
    @Test
    void ecsFormatProducesParseableJsonForASampleLogLine(CapturedOutput output) {
        ConfigurableApplicationContext context = realAppBuilder().run(realAppArgs());
        try {
            List<JsonNode> jsonLines = parseAllJsonLines(output);
            assertThat(jsonLines)
                    .as("expected at least one captured stdout line to parse as a JSON object "
                            + "under logging.structured.format.console=ecs, but captured output was:\n"
                            + output.getOut())
                    .isNotEmpty();
            assertThat(jsonLines).anySatisfy(node -> assertThat(node.has("message")).isTrue());
        } finally {
            context.close();
        }
    }

    // Failure test 7 (Section 5.7): the real application, booted with
    // logging.structured.format.console=ecs, produces a valid JSON startup guard INFO line with
    // message, log.level, and log.logger fields. Field shape confirmed by actually running
    // Spring Boot's real ElasticCommonSchemaStructuredLogFormatter (org.springframework.boot
    // .logging.logback.ElasticCommonSchemaStructuredLogFormatter#jsonMembers, Spring Boot 4.1.1
    // sources) rather than assumed from the plan doc's illustrative example line: the formatter
    // nests level/logger under a "log" object (log.level / log.logger as a JSON *path*, not a
    // flat dotted key) -- so this test navigates node.path("log").path("level"), not
    // node.get("log.level").
    @Test
    void startupGuardLineUnderEcsFormatIsValidJsonWithMessageLevelAndLoggerFields(CapturedOutput output) {
        ConfigurableApplicationContext context = realAppBuilder().run(realAppArgs());
        try {
            List<JsonNode> jsonLines = parseAllJsonLines(output);
            Optional<JsonNode> guardLine = jsonLines.stream()
                    .filter(node -> node.path("log").path("logger").asString("")
                            .contains("StartupGuardBeanFactoryPostProcessor"))
                    .findFirst();

            assertThat(guardLine)
                    .as("expected a parseable JSON line from StartupGuardBeanFactoryPostProcessor "
                            + "in captured output:\n" + output.getOut())
                    .isPresent();

            JsonNode node = guardLine.get();
            assertThat(node.path("log").path("level").asString()).isEqualTo("INFO");
            assertThat(node.path("message").asString()).contains("DEV");
            assertThat(node.path("log").path("logger").asString())
                    .contains("StartupGuardBeanFactoryPostProcessor");
        } finally {
            context.close();
        }
    }

    // Failure test 6 (Section 5.6): a real log line, parsed with an actual JSON parser, has
    // requestId as a field equal to the value the filter generated for that request -- proves
    // the MDC-to-JSON-field mechanism works end to end against a real HTTP request, not just
    // that the right substring appears somewhere in raw text.
    @Test
    void realHttpRequestProducesAJsonLogLineWithMatchingRequestIdField(CapturedOutput output) throws Exception {
        ConfigurableApplicationContext context = realAppBuilder().run(realAppArgs());
        try {
            int port = context.getEnvironment().getProperty("local.server.port", Integer.class);
            assertThat(port).as("embedded web server must have started on a random port").isNotNull();

            HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create("http://localhost:" + port + "/actuator/health"))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            Optional<String> responseRequestId = response.headers().firstValue("Rndr-Id");
            assertThat(responseRequestId)
                    .as("expected the Rndr-Id response header to be set by the request-id filter")
                    .isPresent();

            List<JsonNode> jsonLines = parseAllJsonLines(output);
            Optional<JsonNode> lineWithRequestId = jsonLines.stream()
                    .filter(node -> node.has("requestId"))
                    .filter(node -> node.get("requestId").asString("").equals(responseRequestId.get()))
                    .findFirst();

            assertThat(lineWithRequestId)
                    .as("expected a captured JSON log line whose requestId field equals the "
                            + "Rndr-Id response header (" + responseRequestId.orElse("<absent>")
                            + "), captured output was:\n" + output.getOut())
                    .isPresent();
        } finally {
            context.close();
        }
    }
}
