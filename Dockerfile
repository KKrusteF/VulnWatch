# syntax=docker/dockerfile:1

# ---- Build stage: compile the app with the Gradle wrapper on a full JDK ----
FROM eclipse-temurin:21-jdk AS build
WORKDIR /workspace

COPY gradlew settings.gradle build.gradle ./
COPY gradle ./gradle
# Strip Windows line endings in case the repo was checked out on Windows.
RUN sed -i 's/\r$//' gradlew && chmod +x gradlew

COPY src ./src
# The cache mount keeps Gradle itself and the downloaded dependencies between image builds,
# so only the first build downloads everything.
RUN --mount=type=cache,target=/root/.gradle ./gradlew --no-daemon bootJar

# ---- Runtime stage: only a JRE and the executable jar ----
FROM eclipse-temurin:21-jre
RUN groupadd --system vulnwatch && useradd --system --gid vulnwatch vulnwatch
WORKDIR /app
COPY --from=build /workspace/build/libs/*.jar /app/app.jar
USER vulnwatch
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
