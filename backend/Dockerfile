FROM eclipse-temurin:17-jre

WORKDIR /app

# Copy pre-built jar
COPY target/api-security-analyzer-1.0.0.jar app.jar

# Expose port
EXPOSE 8080

# Run application
ENTRYPOINT ["java", "-jar", "app.jar"]

