#!/bin/bash

echo "🚀 Starting API Security Analyzer Backend..."

# Check if Java is installed
if ! command -v java &> /dev/null; then
    echo "❌ Java not found. Please install Java 17+"
    exit 1
fi

# Check Java version
JAVA_VERSION=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}')
echo "✅ Java version: $JAVA_VERSION"

# Build project
echo "📦 Building project..."
./mvnw clean package -DskipTests

# Run application
echo "🏃 Running application..."
java -jar target/api-security-analyzer-1.0.0.jar

