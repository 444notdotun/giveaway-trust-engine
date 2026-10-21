# syntax=docker/dockerfile:1

# Pinned to an exact Temurin patch release, by tag AND digest, not a floating
# major-version tag -- the same Dockerfile must not silently build a different
# JVM patch on a later date. Looked up directly against Docker Hub at the time
# this was written (2026-10); re-verify and re-pin when bumping deliberately.
FROM eclipse-temurin@sha256:07a4ee373cd86f337e62cb8149f1e0a9f08aaf3a18c27509a493dda119fb480c AS build
# eclipse-temurin:25.0.4.1_1-jdk-jammy

WORKDIR /app

# Dependency layer first, cached separately from source changes.
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
RUN ./mvnw -B dependency:go-offline

# Now the source, and build. Tests already ran in CI's verify job.
COPY src/ src/

ARG COMMIT_SHA
RUN test -n "$COMMIT_SHA" || (echo "COMMIT_SHA build arg is required and must not be empty" >&2 && exit 1)

RUN ./mvnw -B -DskipTests package

FROM eclipse-temurin@sha256:e0d8c47eccd7ec82d635542dfcd1f2b1293add6bdd7ffbeb650f8ec1b1335425 AS runtime
# eclipse-temurin:25.0.4.1_1-jre-jammy

RUN groupadd --gid 10001 appgroup \
    && useradd --uid 10001 --gid appgroup --no-create-home --shell /usr/sbin/nologin appuser

WORKDIR /app

COPY --from=build /app/target/*.jar app.jar

ARG COMMIT_SHA
ENV APP_COMMIT_SHA=${COMMIT_SHA}

USER appuser

# Render sets PORT at runtime; server.port reads it (see application.properties).
# No EXPOSE of a fixed port, since the actual listening port is runtime-determined.

# JVM flags reasoned against Render's free-tier instance (512 MB / 0.1 CPU) --
# see docs/slices/02a-ci-and-staging.md Section 1 for the full reasoning.
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=65.0", "-XX:+UseSerialGC", "-Xss512k", "-XX:+ExitOnOutOfMemoryError", "-jar", "app.jar"]
