# Slice 2: Startup guard and typed config

CRITICAL REVIEW slice. PRD refs: Section 13 (Environments — dev/staging/production are not symmetric), Section 18 (Bachs sandbox/live base URLs are an explicit open item). BUILD_ORDER item 2.

## Decision: Bachs URL values

CLAUDE.md lists "sandbox and live base URLs" by name as a never-guess item, and PRD Section 18 lists them as open, owned by Adedotun. **Adedotun has now provided the real values directly in chat**, which is exactly how a never-guess item is supposed to get resolved — not by guessing, by asking and being told:

- Production (live): `https://api.bachs.io`
- Sandbox: `https://sandbox-api.bachs.io`

These are not secrets (public API base URLs, not credentials), so they're safe to commit as real values in `.env.example` and as the actual configured values for `application.properties`'s env-var defaults — see the "existing config and tests" decision below. `app.bachs.sandbox-base-url` and `app.bachs.live-base-url` are still plain `@ConfigurationProperties` string fields with **no defaults baked into Java code** (CLAUDE.md: "no defaults for secrets" — these specific values aren't secret, but the principle extends to any config where silently defaulting risks pointing at the wrong rail, which is the exact failure this guard exists to catch); the real values live in `.env`/`.env.example`/deployment config, not hardcoded in `AppProperties` or the guard.

Unit tests for the guard's own logic still use clearly-fake, distinct values (e.g. `https://sandbox.example.test`, `https://live.example.test`) rather than the real Bachs URLs — this keeps the guard's test suite decoupled from Bachs ever changing their domain, and the guard's logic (exact-match classification) doesn't care what the strings actually are. The two "real application wiring" tests (see Tests section) and `.env.example`/`application.properties` are where the real, now-confirmed URLs actually appear.

This resolves the PRD Section 18 open item for the base URLs specifically. The *rest* of that row — webhook signature header names, retry/event-id semantics, response codes — is still unverified and still deferred to slice 10's Bachs sandbox check; only the two base URLs were asked about and answered here.

## Decision: guard rule scope

Confirmed with Adedotun: enforce one general rule, not four special cases. **DEV and STAGING must be configured with the sandbox base URL; PRODUCTION must be configured with the live base URL.** Any other combination refuses to start. This covers the four named tests as instances of one rule, plus the two untested combinations (dev+live, staging+live is actually tested as the refusal case — the only combination not explicitly named is dev+live, which also refuses under this rule, consistent with "dev must never talk to real payment infrastructure").

The classification of "which base URL is configured" happens by exact string equality against `app.bachs.sandbox-base-url` / `app.bachs.live-base-url`, never substring/contains (BUILD_ORDER: "Exact URL comparison, never substring" — a substring check would let `https://evil.sandbox.example.test.attacker.com` falsely classify as sandbox, or similar). If the configured value matches neither known URL exactly, that's also a startup failure (fail closed on an unrecognized URL, not fail open).

**Sandbox equals live is also a refusal, in every environment.** If `app.bachs.sandbox-base-url` and `app.bachs.live-base-url` are ever configured to the same value, exact-match classification can't tell sandbox and live apart — the check "`configured.equals(sandboxUrl)`" would pass in every environment regardless of which rail is actually meant, letting DEV silently run against what is really the live URL. This is exactly the failure this guard exists to prevent, so it's checked explicitly and first, before any classification happens, and fails closed regardless of `environment`.

## Decision: single source for the configured URL

`app.bachs.base-url` is the only field any later Bachs client code (slice 10) is ever allowed to read to make an actual API call. `sandbox-base-url` and `live-base-url` exist solely so the guard can classify which rail `base-url` currently points at — they are reference values for comparison, never call targets themselves. This boundary is stated here so slice 10 doesn't accidentally wire the client to `liveBaseUrl` directly "for safety" or similar, which would bypass the guard's classification entirely (the client would then always hit live regardless of what the guard approved).

## Typed config

Per CLAUDE.md ("Config through @ConfigurationProperties records validated at startup. No scattered @Value"), for consumption by the rest of the app (slice 10's Bachs client reads `bachs.baseUrl()` from this bean once it exists):

```java
@ConfigurationProperties(prefix = "app")
public record AppProperties(
    Environment environment,
    BachsProperties bachs
) {
    public record BachsProperties(
        String sandboxBaseUrl,
        String liveBaseUrl,
        String baseUrl   // the configured value actually in effect; the only field a client may call
    ) {}
}
```

This record carries no Jakarta Bean Validation annotations, which is a deliberate deviation from CLAUDE.md's usual "Config through @ConfigurationProperties records validated at startup" pattern — see the "Deviation from CLAUDE.md" note two sections below for why the required-ness checks live in the guard instead of `@Validated`.

## Decision: why the guard is a `BeanFactoryPostProcessor`, not a bean or `ApplicationRunner` — corrected reasoning

An earlier draft of this doc claimed the embedded web server starts accepting connections inside `onRefresh()`, and used that to argue an ordinary bean's constructor/`@PostConstruct` would run too late. **That claim was wrong, and has been corrected after reading the actual Spring Boot 4.1.1 source** (`spring-boot-web-server-4.1.1-sources.jar`):

- `ServletWebServerApplicationContext.onRefresh()` calls `createWebServer()`, which only **creates** the `WebServer` instance (`factory.getWebServer(...)`) and registers a `WebServerStartStopLifecycle` singleton. It does not call `webServer.start()`.
- `WebServerStartStopLifecycle` (`org.springframework.boot.web.server.servlet.context.WebServerStartStopLifecycle`) implements `SmartLifecycle`. Its `start()` method — the one that actually calls `this.webServer.start()`, which is what makes the embedded server begin accepting connections — is invoked by the `LifecycleProcessor` during `finishRefresh()`, the step that runs **after** `finishBeanFactoryInitialization()`.
- `finishBeanFactoryInitialization()` is the phase that eagerly instantiates ordinary singleton beans, runs `@PostConstruct` methods, and (per Boot's own `SpringApplication.callRunners()`, invoked after `run()` completes) is also before `ApplicationRunner`/`CommandLineRunner`.

So an ordinary bean's constructor or `@PostConstruct` check **would** run before the port opens — the original "cannot be a bean because the port is already open" argument is overstated and is dropped.

**The real reason to use a `BeanFactoryPostProcessor` is different and still solid**: `invokeBeanFactoryPostProcessors()` runs *before* `finishBeanFactoryInitialization()`, which means a `BeanFactoryPostProcessor` is guaranteed to run before **any other bean in the context is created** — not just before the port opens, but before the `DataSource`, the Flyway migration runner, the Redis connection factory, or anything else that might attempt real I/O as soon as it's constructed (e.g. Hikari's pool initialization, Flyway's migration check). An ordinary bean's constructor-time check, by contrast, is instantiated as part of the same `finishBeanFactoryInitialization()` sweep as every other singleton — Spring does not guarantee it runs first relative to siblings with no dependency relationship to it. The only way to force that ordering on a plain bean would be `@DependsOn` wired onto every other bean in the context, which is fragile and silently broken by anyone who adds a new bean later without remembering to depend on the guard. A `BeanFactoryPostProcessor` gets this ordering structurally, with no per-bean wiring required anywhere.

So the guard is implemented as a `BeanFactoryPostProcessor` (`StartupGuardBeanFactoryPostProcessor`, also implementing `EnvironmentAware` to get access to `ConfigurableEnvironment`), not a bean with a constructor-time check and not an `ApplicationRunner`. It reads the raw config directly via Spring's `Binder` API (`Binder.get(environment).bind("app.environment", String.class)`, one property at a time, not binding the whole `AppProperties` record at once) so it controls its own error messages precisely, independent of `@ConfigurationProperties`' own binding/validation lifecycle (which runs during ordinary bean instantiation — i.e. after the guard, by design, since the guard must not depend on the thing it's validating).

**Laziness is structurally not a concern either way**: `BeanFactoryPostProcessor` invocation is unaffected by `spring.main.lazy-initialization` (that setting only defers ordinary bean instantiation; `BeanFactoryPostProcessor`s must always run eagerly for the container to function, since they can rewrite bean definitions before anything is instantiated). `spring.main.lazy-initialization` is not set anywhere in `application.properties` for this project — confirmed absent, and this is asserted explicitly as a decision so a future slice adding it globally doesn't need to reconsider whether it affects this guard (it structurally can't).

## Environment enum

```java
public enum Environment { DEV, STAGING, PRODUCTION }
```

Read from `app.environment` as a raw string by the guard (via `Binder`, parsed with `Environment.valueOf(envRaw.trim())`) — not defaulted. **Matching is exact and case-sensitive**, not Spring's usual relaxed, case-insensitive enum binding: lowercase `dev` is refused, naming `app.environment` and the bad value, same as any other unrecognized value. This extends BUILD_ORDER's "exact comparison, never substring" rule — originally stated for the Bachs URLs — to the environment value itself, on the same reasoning: a loose match here is exactly the kind of silent accommodation that could let a typo'd config value through unnoticed. An unset, blank, unresolved-placeholder, or unparseable value is a named failure (see cases below), never a silent fallback to `DEV` or a case-corrected guess.

## The guard itself (`StartupGuardBeanFactoryPostProcessor`)

```
sandboxUrl  = binder.bind("app.bachs.sandbox-base-url", String.class)
liveUrl     = binder.bind("app.bachs.live-base-url", String.class)
configured  = binder.bind("app.bachs.base-url", String.class)
envRaw      = binder.bind("app.environment", String.class)

if (envRaw is blank/absent)       -> ERROR log, throw StartupGuardException("app.environment is required")
if (envRaw does not parse)        -> ERROR log, throw StartupGuardException("app.environment '" + envRaw + "' is not DEV, STAGING, or PRODUCTION")
if (sandboxUrl is blank/absent)   -> ERROR log, throw StartupGuardException("app.bachs.sandbox-base-url is required")
if (liveUrl is blank/absent)      -> ERROR log, throw StartupGuardException("app.bachs.live-base-url is required")
if (configured is blank/absent)   -> ERROR log, throw StartupGuardException("app.bachs.base-url is required")

if (sandboxUrl.equals(liveUrl))   -> ERROR log, throw StartupGuardException("app.bachs.sandbox-base-url and app.bachs.live-base-url must not be the same value")

mode = if (configured.equals(sandboxUrl)) SANDBOX
       else if (configured.equals(liveUrl)) LIVE
       else { ERROR log, throw StartupGuardException("app.bachs.base-url does not exactly match the configured sandbox or live URL") }

allowed = switch (environment) {
    DEV, STAGING -> mode == SANDBOX
    PRODUCTION   -> mode == LIVE
}

if (!allowed) { ERROR log; throw StartupGuardException(environment + " must not run with Bachs in " + mode + " mode") }

INFO log: environment + mode    // only reached if every check above passed
```

Every `ERROR log` line above states the specific property name and/or environment/mode involved, but **never** the literal URL string values (`sandboxUrl`, `liveUrl`, `configured`) — matching the INFO line, which likewise logs only `environment` and the resolved `mode` enum, never a URL. Throwing from a `BeanFactoryPostProcessor` fails `postProcessBeanFactory()`, which fails `invokeBeanFactoryPostProcessors()`, which fails `refresh()`, which fails `SpringApplication.run()` — "refuses to start" with Spring Boot's own non-zero exit, no custom process-exit code needed — and, per the corrected reasoning above, failing before the `DataSource`, Flyway, Redis, or any other bean in the context is ever created.

## Failure cases

1. **dev + sandbox** — starts. Happy path, one of the four BUILD_ORDER-required tests.
2. **staging + live** — refuses (environment/mode mismatch).
3. **production + sandbox** — refuses (environment/mode mismatch).
4. **production + live** — starts. Happy path, one of the four BUILD_ORDER-required tests.
5. **dev + live** — refuses (environment/mode mismatch; the rule's logical consequence, not separately named by BUILD_ORDER but required since the rule is general per Adedotun's direction).
6. **unrecognized base URL, exact-match edge cases** — refuses in every case, each a distinct test proving the comparison is exact, not substring/contains/case-insensitive:
   - a. `base-url` is a typo / entirely different value.
   - b. `base-url` is the real sandbox URL **plus a trailing slash** (`https://sandbox.example.test/`).
   - c. `base-url` is the real sandbox URL in **different case** (`https://SANDBOX.example.test`).
   - d. `base-url` is an exact **prefix** of the real sandbox URL (`https://sandbox.example.te`).
7. **sandbox URL equals live URL** — refuses regardless of `environment` (DEV, STAGING, and PRODUCTION each get their own test), per the decision above.
8. **missing/invalid config, each a separate named failure:**
   - a. `app.bachs.sandbox-base-url` blank.
   - b. `app.bachs.live-base-url` blank.
   - c. `app.bachs.base-url` blank.
   - d. `app.environment` missing entirely.
   - e. `app.environment` set to an invalid value (`PROD` — not one of `DEV`/`STAGING`/`PRODUCTION`).

No race/timeout/crash cases apply — this is a single startup-time check with no concurrency, no external calls, and no database/Redis dependency.

## Tests

No PRD Section 17 row maps directly to this slice (the acceptance criteria table has no startup-guard row — this slice's test obligations come from BUILD_ORDER's four named tests plus the cases above). **Not `@SpringBootTest`** — a full Spring Boot context pulls in `DataSourceAutoConfiguration`, `FlywayAutoConfiguration`, and Redis autoconfiguration, none of which this slice needs or should depend on to prove the guard works, and that dependency would make every refusal test ambiguous (did it refuse because of the guard, or because there's no real datasource configured?). Instead: `org.springframework.boot.test.context.runner.ApplicationContextRunner`, which boots a bare `AnnotationConfigApplicationContext` with no autoconfiguration unless explicitly imported. Each test registers only `StartupGuardBeanFactoryPostProcessor` and sets properties via `.withPropertyValues(...)`.

- Cases 1 and 4 (dev+sandbox, production+live): `contextRunner.run(context -> assertThat(context).hasNotFailed())`.
- Cases 2, 3, 5 (staging+live, production+sandbox, dev+live): `.run(context -> assertThat(context).hasFailed())`, and the failure's root cause message names the environment and mode.
- Case 6a-d (unrecognized URL incl. trailing slash / case / prefix): each its own test, context fails, message names `app.bachs.base-url` specifically (distinct wording from the environment-mismatch message, so an operator can tell "wrong URL entirely" apart from "right rail, wrong environment").
- Case 7 (sandbox == live), tested once per environment (3 tests): context fails, message names both `app.bachs.sandbox-base-url` and `app.bachs.live-base-url`.
- Case 8a-e (5 separate tests): context fails, each message names the specific blank/missing/invalid property.

Every test (success and failure) also asserts the corresponding log line via `@ExtendWith(OutputCaptureExtension.class)` / `CapturedOutput` (works standalone with `ApplicationContextRunner`, no `@SpringBootTest` needed): success tests assert the INFO line is present and contains `environment`/`mode`; failure tests assert the ERROR line is present and contains the property/environment/mode detail; **every test, success and failure alike, asserts the literal configured URL strings used in that test never appear anywhere in the captured output.**

17 tests total so far (cases 1-5 is 5, case 6a-d is 4, case 7 × 3 environments is 3, case 8a-e is 5 — corrected arithmetic; an earlier draft of this doc said "16", which undercounted its own itemized list), all pure `ApplicationContextRunner` tests — no database, no Redis, no Testcontainers. **But every one of them registers `StartupGuardBeanFactoryPostProcessor` by hand**, which proves the guard's own logic is correct, not that it's actually wired into the real application. A bug like a non-`static` `@Bean` factory method for a `BeanFactoryPostProcessor` (Spring requires these to be `static` so they can run before the declaring `@Configuration` class is itself fully processed — a non-static one is either silently skipped or processed too late, with only a log warning, not a hard failure) or the class simply not being picked up by component scanning would pass all 17 tests above and still leave the real app unprotected.

**Two more tests prove the gate actually exists in the real app**, booting the actual `GiveawayTrustEngineApplication` class (not a hand-assembled `ApplicationContextRunner`) via `SpringApplicationBuilder`, with `DataSourceAutoConfiguration`, `FlywayAutoConfiguration`, and `DataRedisAutoConfiguration` excluded via `spring.autoconfigure.exclude` (exact FQNs verified against the actual Boot 4.1.1 jars, not guessed — Boot 4 moved these out of the classic `org.springframework.boot.autoconfigure.*` package: `org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration`, `org.springframework.boot.flyway.autoconfigure.FlywayAutoConfiguration`, `org.springframework.boot.data.redis.autoconfigure.DataRedisAutoConfiguration`). Excluding them is safe specifically *because* the guard runs before any bean — including those three — is created, so excluding them only removes unrelated noise (a real Postgres/Redis connection attempt), not something the guard's own correctness depends on:
- **Bad combination** (`STAGING` + `https://api.bachs.io`, the real live URL): assert the real application fails to start, with `StartupGuardException` in the cause chain and the expected message. No Postgres or Redis needed — the guard fails before those beans would even be created.
- **Valid combination** (`DEV` + `https://sandbox-api.bachs.io`, the real sandbox URL): assert the real application starts successfully (context is active) with those three autoconfigurations excluded. This proves the valid path gets *past* the guard in the real, actually-wired application — not just in a hand-built test context.

These two tests use the real, confirmed Bachs URLs deliberately (unlike the 17 logic tests above, which use fake values) — this is the test suite's one place that would actually catch it if Adedotun later says the URLs above were wrong.

19 tests from the originally-approved plan. Two further review rounds added 7 more directly in `StartupGuardTest` (the unresolved/partial-placeholder pair, four whitespace-only cases, and the lowercase-environment case — see "Round 2 review" below) — 26 tests in `StartupGuardTest` by the end.

## `AppProperties` binding test, and the deviation from CLAUDE.md

`StartupGuardBeanFactoryPostProcessor` reads every value through `Binder` directly, independently of `AppProperties`. Nothing above actually proves `AppProperties` itself binds correctly — and slice 10's Bachs client will trust that record completely once it exists, so a 27th test (across both files) binds a valid configuration (all three URLs plus the enum) through the normal `@ConfigurationProperties` mechanism and asserts the resulting `AppProperties` has the expected `environment` and all three `bachs` fields populated correctly. This also confirms `AppProperties` is actually registered for binding — via `@EnableConfigurationProperties(AppProperties.class)` on a `@Configuration` class (not component-scanning a `record`, which Boot does not do automatically for `@ConfigurationProperties` types) — so a future consumer doesn't have to discover it's unregistered the hard way.

**Deviation from CLAUDE.md, stated explicitly**: CLAUDE.md says config should be "`@ConfigurationProperties` records validated at startup" via `@Validated` + Jakarta Bean Validation. This slice doesn't use `@Validated` on `AppProperties` for the required-ness of `environment`/the three URLs. Reason: `@ConfigurationProperties` validation runs via `ConfigurationPropertiesBindingPostProcessor`, which executes during ordinary bean instantiation (`finishBeanFactoryInitialization()`) — exactly the phase the guard is designed to run *before*, per the decision above. If required-ness were enforced only through `@Validated` on `AppProperties`, a missing property would fail at the wrong, later point in startup (and with Spring's generic binding-failure message, not one naming the specific business rule violated), defeating the purpose of making this a `BeanFactoryPostProcessor` in the first place. So the guard duplicates the required-ness checks itself, early, with its own messages; `AppProperties` stays a plain unvalidated record whose only job is to exist as a typed, bindable shape for code that runs after the guard has already passed.

## Decision: existing config and tests must be updated in this slice

`GiveawayTrustEngineApplicationTests` (self-contained via Testcontainers since slice 1) and any other test that boots the real application context now go through `StartupGuardBeanFactoryPostProcessor` too — once this slice lands, those contexts won't start at all without the four `app.*` properties set to something that passes the guard. These get fixed in this same slice, not left broken for a later one to discover:
- `GiveawayTrustEngineApplicationTests`: add `app.environment=DEV` and the three `app.bachs.*` properties to its `@DynamicPropertySource`, alongside the existing datasource/Redis overrides — `sandbox-base-url=https://sandbox-api.bachs.io`, `live-base-url=https://api.bachs.io`, `base-url=https://sandbox-api.bachs.io` (DEV must be sandbox, per the guard rule).
- `application.properties`: add the same four properties bound to env vars with **no defaults** (consistent with the "no defaults for secrets/config that could silently misconfigure" reasoning above) — `app.environment=${APP_ENVIRONMENT}`, `app.bachs.sandbox-base-url=${BACHS_SANDBOX_BASE_URL}`, `app.bachs.live-base-url=${BACHS_LIVE_BASE_URL}`, `app.bachs.base-url=${BACHS_BASE_URL}`.
- `.env.example`: add the same four env var names with the real, now-confirmed values — `APP_ENVIRONMENT=DEV`, `BACHS_SANDBOX_BASE_URL=https://sandbox-api.bachs.io`, `BACHS_LIVE_BASE_URL=https://api.bachs.io`, `BACHS_BASE_URL=https://sandbox-api.bachs.io` — plus a comment noting the base URLs are confirmed but webhook signature/retry/response-code details are still unverified pending the Bachs sandbox (slice 10). `APP_ENVIRONMENT` must be uppercase: the guard's environment match is case-sensitive (see the strict-matching decision above), so a lowercase example value would make the one thing every new developer copy-pastes fail the guard immediately — caught by the security review in this slice.
- `.env` (the developer's own local, gitignored file): same four vars with the same dev-safe values (sandbox for `base-url`), so `./mvnw -B verify` keeps working locally without manual setup after this slice merges.

## Round 2 review: a real bug, and tightened tests

**The Render-crash bug.** `application.properties` has `app.environment=${APP_ENVIRONMENT}` with no default. With `APP_ENVIRONMENT` unexported — the most realistic real-world failure, a forgotten env var on a Render deploy — Spring leaves the property as the literal unresolved string `${APP_ENVIRONMENT}`: not null, not blank, so the original null/blank checks didn't catch it. It fell through to `Environment.valueOf(...)`, which failed, producing `app.environment '${APP_ENVIRONMENT}' is not one of DEV, STAGING, or PRODUCTION` — a raw placeholder leaking into an operator-facing log line instead of a clear "set this env var" message. Reproduced on the real app (`spring-boot:run` with no `APP_*` vars exported) before fixing, and again after, to confirm the fix: `isUnset()` now also treats any value containing the literal `${` fragment as unset — covering both a value that's entirely an unresolved placeholder and one where the placeholder is only part of the value (e.g. `https://${HOST}.example.test`) — so both collapse to the same clear `"<property> is required"` message, never a leaked placeholder or a binding stack trace. Covered by `unresolvedPlaceholderEnvironmentRefusesWithClearMessage` and `partialPlaceholderBaseUrlRefusesWithClearMessage`.

**The bad-combination real-wiring test now proves what it claims to.** It previously excluded `DataSourceAutoConfiguration`/`FlywayAutoConfiguration`/`DataRedisAutoConfiguration`, which meant it never actually exercised the claim that the guard runs before those beans exist — it just avoided needing them. Removed the exclusions from that one test (the valid-combination test keeps them, since that one needs to actually finish starting); it now runs with the Docker Compose stack fully stopped and no `DB_HOST`/`POSTGRES_*`/etc. env vars set, and still fails with `StartupGuardException` as the root cause. If the guard ever stopped running before the `DataSource` bean, this test would fail for the wrong reason (a Hikari/Flyway connection error) instead.

**Whitespace-only values are refused, same as blank — mutation-verified, with a real test-infrastructure finding along the way.** Added four whitespace-only tests (`app.environment`, and all three `app.bachs.*` URLs). First attempt used `withPropertyValues("key=   ")`, which silently failed to test anything new: `TestPropertyValues.Pair.parse` calls `value.trim()` while parsing `"key=value"` strings, so a whitespace-only value becomes `""` before the guard ever sees it — identical to the existing blank tests. Confirmed by mutating `isBlank()` → `isEmpty()`: nothing went red. Fixed by injecting the raw value through a `MapPropertySource` directly (bypassing `TestPropertyValues` entirely) via a `guardedContextWithRawProperty` helper, so the literal `"   "` survives to the guard. Re-ran the mutation: 2 of 4 tests still passed (`whitespaceOnlyConfiguredBaseUrlRefuses`, `whitespaceOnlyEnvironmentRefuses`) — their assertions only checked `contains(propertyName)`, and under the mutation the guard fell through to a *different* real check (the mismatch check, or enum-parse failure) that happened to also name the same property, giving a misleadingly plausible-looking message. Tightened both to assert the exact `"<property> is required"` message (`isEqualTo`, matching the placeholder tests' precision) — re-ran the mutation again: all 4 now correctly go red. Restored afterward.

**Log assertions tightened and mutation-verified.** Every refusal test now asserts, via `assertErrorLogLine`, a single captured output line containing `"ERROR"`, the guard's own logger name, and the specific property/environment/mode detail — not three independent `.contains(...)` checks that could each match on a different line. Verified by mutating `fail()` to drop the `log.error(...)` call while keeping the `throw`: all 22 refusal tests with a log assertion correctly went red; the two happy-path tests and the two real-app-wiring tests (which don't assert this guard's log output the same way) were unaffected, as expected. No decorative log assertion survived.

## Logs and metrics

Per CLAUDE.md ("Observability required in every slice") and Section 14's general principle, applied narrowly since this slice has no `giveawayId` (nothing giveaway-specific happens at startup):
- On successful start: one INFO structured log line stating the resolved `environment` and `mode` (SANDBOX/LIVE) only — never the URL values — so an operator can confirm which rail a running instance is actually talking to without reading its env vars or risking the URL itself landing in a log aggregator.
- On refusal: one ERROR structured log line stating the environment, the resolved mode (or the specific property name, for the blank/missing/unrecognized cases), and why it was refused — again never the URL values — logged before the exception propagates and fails startup. This is the one line an operator watching a failed deploy would see.
- No `giveaway_logs` row — that table is scoped to giveaway pipeline events (Section 14), and startup happens before any giveaway exists. No Micrometer counter either: a refused startup never reaches a running state where a counter could be scraped; the ERROR log line, visible in Render's own log stream, is the operator-facing signal for this failure mode.
