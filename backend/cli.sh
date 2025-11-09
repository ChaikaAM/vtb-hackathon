#!/bin/bash

# API Security Analyzer CLI wrapper script
# Использование: ./cli.sh [OPTIONS]

# Определяем директорию скрипта
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLI_JAR="${SCRIPT_DIR}/target/api-security-cli-cli.jar"

# Если не найден с classifier, пробуем без него (для обратной совместимости)
if [ ! -f "$CLI_JAR" ]; then
    CLI_JAR="${SCRIPT_DIR}/target/api-security-cli.jar"
fi

# Проверяем наличие JAR файла
if [ ! -f "$CLI_JAR" ]; then
    echo "Ошибка: CLI JAR файл не найден: $CLI_JAR"
    echo "Сначала выполните сборку: mvn clean package"
    exit 1
fi

# Проверяем наличие Java
if ! command -v java &> /dev/null; then
    echo "Ошибка: Java не установлена или не найдена в PATH"
    exit 1
fi

# Проверяем версию Java (нужна Java 17+)
JAVA_VERSION=$(java -version 2>&1 | awk -F '"' '/version/ {print $2}' | cut -d'.' -f1)
if [ "$JAVA_VERSION" -lt 17 ]; then
    echo "Ошибка: Требуется Java 17 или выше. Текущая версия: $JAVA_VERSION"
    exit 1
fi

# Проверяем структуру JAR (Spring Boot JAR имеет BOOT-INF структуру)
if jar tf "$CLI_JAR" 2>/dev/null | grep -q "^BOOT-INF/"; then
    # Это Spring Boot JAR - используем правильный способ запуска
    # Распаковываем JAR во временную директорию и запускаем с правильным classpath
    TEMP_DIR=$(mktemp -d)
    trap "rm -rf $TEMP_DIR" EXIT

    cd "$TEMP_DIR"
    jar xf "$CLI_JAR" >/dev/null 2>&1

    # Формируем classpath
    CLASSPATH="BOOT-INF/classes"
    for jar in BOOT-INF/lib/*.jar; do
        CLASSPATH="$CLASSPATH:$jar"
    done

    # Запускаем CLI класс
    java -cp "$CLASSPATH" com.vtb.apisecurity.cli.ApiSecurityCli "$@"
    EXIT_CODE=$?
else
    # Обычный JAR - запускаем стандартным способом
    java -jar "$CLI_JAR" "$@"
    EXIT_CODE=$?
fi

# Для Jenkins - сохраняем URL отчета в переменную окружения, если он был выведен
if [ -n "$REPORT_URL" ]; then
    export REPORT_URL
fi

exit $EXIT_CODE

