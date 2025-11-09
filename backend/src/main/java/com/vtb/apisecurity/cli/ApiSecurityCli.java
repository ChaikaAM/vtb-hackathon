package com.vtb.apisecurity.cli;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.vtb.apisecurity.model.ScanRequest;
import com.vtb.apisecurity.model.ScanResult;

/**
 * CLI инструмент для запуска анализа API безопасности
 */
public class ApiSecurityCli {
    
    private static final String DEFAULT_SERVER_URL = "https://vtb.seag.pro";
    private static final int DEFAULT_TIMEOUT_SECONDS = 600; // 10 minutes
    
    private final String serverUrl;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    
    public ApiSecurityCli(String serverUrl) {
        this.serverUrl = serverUrl.endsWith("/") ? serverUrl.substring(0, serverUrl.length() - 1) : serverUrl;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                .build();
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
    }
    
    public ScanResult runAnalysis(ScanRequest request) throws IOException, InterruptedException {
        String url = serverUrl + "/api/analysis/scan";
        
        String requestBody = objectMapper.writeValueAsString(request);
        
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .timeout(Duration.ofSeconds(DEFAULT_TIMEOUT_SECONDS))
                .build();
        
        System.out.println("Отправка запроса на анализ...");
        System.out.println("URL: " + url);
        System.out.println("OpenAPI URL: " + request.getOpenApiUrl());
        System.out.println("API Base URL: " + request.getApiBaseUrl());
        
        HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        
        if (response.statusCode() != 200) {
            throw new IOException("Ошибка при выполнении запроса. HTTP статус: " + response.statusCode() + 
                    "\nОтвет: " + response.body());
        }
        
        ScanResult result = objectMapper.readValue(response.body(), ScanResult.class);
        return result;
    }
    
    public static void main(String[] args) {
        if (args.length == 0 || args[0].equals("--help") || args[0].equals("-h")) {
            printUsage();
            System.exit(0);
        }
        
        try {
            CliArguments cliArgs = parseArguments(args);
            
            ScanRequest.ScanOptions options = new ScanRequest.ScanOptions();
            options.setEnableStaticAnalysis(cliArgs.enableStaticAnalysis);
            options.setEnableDynamicTesting(cliArgs.enableDynamicTesting);
            options.setEnableContractValidation(cliArgs.enableContractValidation);
            options.setEnableAiAnalysis(cliArgs.enableAiAnalysis);
            options.setTimeoutMs(cliArgs.timeoutMs);
            options.setMaxConcurrentRequests(cliArgs.maxConcurrentRequests);
            
            ScanRequest request = new ScanRequest();
            request.setOpenApiUrl(cliArgs.openApiUrl);
            request.setApiBaseUrl(cliArgs.apiBaseUrl);
            request.setOptions(options);
            
            ApiSecurityCli cli = new ApiSecurityCli(cliArgs.serverUrl);
            
            System.out.println("========================================");
            System.out.println("API Security Analyzer CLI");
            System.out.println("========================================");
            System.out.println();
            
            ScanResult result = cli.runAnalysis(request);
            
            System.out.println();
            System.out.println("========================================");
            System.out.println("Анализ завершен!");
            System.out.println("========================================");
            System.out.println("Scan ID: " + result.getScanId());
            System.out.println("Статус: " + result.getStatus());
            
            if (result.getDurationMs() != null) {
                System.out.println("Длительность: " + result.getDurationMs() + " мс");
            }
            
            if (result.getVulnerabilityCounts() != null && !result.getVulnerabilityCounts().isEmpty()) {
                System.out.println("\nСтатистика уязвимостей:");
                result.getVulnerabilityCounts().forEach((severity, count) -> 
                    System.out.println("  " + severity + ": " + count));
            }
            
            if (result.getTotalEndpoints() > 0) {
                System.out.println("\nСтатистика эндпоинтов:");
                System.out.println("  Всего: " + result.getTotalEndpoints());
                System.out.println("  Протестировано: " + result.getTestedEndpoints());
                System.out.println("  Успешно: " + result.getPassedEndpoints());
                System.out.println("  С ошибками: " + result.getFailedEndpoints());
            }
            
            String reportHtmlUrl = cliArgs.serverUrl + "/api/reports/" + result.getScanId() + "/HTML";
            String reportPageUrl = cliArgs.serverUrl + "/results/" + result.getScanId();
            
            System.out.println();
            System.out.println("========================================");
            System.out.println("Ссылка на отчет:");
            System.out.println(reportHtmlUrl);
            System.out.println();
            System.out.println("Ссылка на страницу отчета:");
            System.out.println(reportPageUrl);
            System.out.println("========================================");
            
            // Для Jenkins - выводим URL в отдельной строке для удобного парсинга
            System.out.println();
            System.out.println("REPORT_URL=" + reportHtmlUrl);
            System.out.println("REPORT_PAGE_URL=" + reportPageUrl);
            
            // Exit code для Jenkins: 0 - успех, 1 - ошибка
            if (result.getStatus() == ScanResult.ScanStatus.FAILED) {
                System.exit(1);
            }
            
        } catch (Exception e) {
            System.err.println("Ошибка: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
    
    private static CliArguments parseArguments(String[] args) {
        CliArguments cliArgs = new CliArguments();
        
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            
            switch (arg) {
                case "--openapi-url":
                case "-o":
                    if (i + 1 < args.length) {
                        cliArgs.openApiUrl = args[++i];
                    }
                    break;
                case "--api-base-url":
                case "-a":
                    if (i + 1 < args.length) {
                        cliArgs.apiBaseUrl = args[++i];
                    }
                    break;
                case "--server-url":
                case "-s":
                    if (i + 1 < args.length) {
                        cliArgs.serverUrl = args[++i];
                    }
                    break;
                case "--enable-static-analysis":
                    cliArgs.enableStaticAnalysis = true;
                    break;
                case "--enable-dynamic-testing":
                    cliArgs.enableDynamicTesting = true;
                    break;
                case "--enable-contract-validation":
                    cliArgs.enableContractValidation = true;
                    break;
                case "--enable-ai-analysis":
                    cliArgs.enableAiAnalysis = true;
                    break;
                case "--timeout-ms":
                    if (i + 1 < args.length) {
                        cliArgs.timeoutMs = Integer.parseInt(args[++i]);
                    }
                    break;
                case "--max-concurrent-requests":
                    if (i + 1 < args.length) {
                        cliArgs.maxConcurrentRequests = Integer.parseInt(args[++i]);
                    }
                    break;
            }
        }
        
        if (cliArgs.openApiUrl == null || cliArgs.openApiUrl.isEmpty()) {
            throw new IllegalArgumentException("--openapi-url (-o) обязателен");
        }
        
        if (cliArgs.apiBaseUrl == null || cliArgs.apiBaseUrl.isEmpty()) {
            throw new IllegalArgumentException("--api-base-url (-a) обязателен");
        }
        
        return cliArgs;
    }
    
    private static void printUsage() {
        System.out.println("API Security Analyzer CLI");
        System.out.println();
        System.out.println("Использование:");
        System.out.println("  java -jar api-security-cli.jar [OPTIONS]");
        System.out.println();
        System.out.println("Обязательные параметры:");
        System.out.println("  -o, --openapi-url URL          URL OpenAPI спецификации");
        System.out.println("  -a, --api-base-url URL         Базовый URL API для тестирования");
        System.out.println();
        System.out.println("Опциональные параметры:");
        System.out.println("  -s, --server-url URL            URL сервера анализа (по умолчанию: https://vtb.seag.pro)");
        System.out.println("  --enable-static-analysis        Включить статический анализ");
        System.out.println("  --enable-dynamic-testing        Включить динамическое тестирование");
        System.out.println("  --enable-contract-validation    Включить валидацию контракта");
        System.out.println("  --enable-ai-analysis            Включить AI анализ (по умолчанию включен)");
        System.out.println("  --timeout-ms MS                 Таймаут в миллисекундах (по умолчанию: 300000)");
        System.out.println("  --max-concurrent-requests N     Максимум одновременных запросов (по умолчанию: 10)");
        System.out.println();
        System.out.println("Примеры:");
        System.out.println("  java -jar api-security-cli.jar \\");
        System.out.println("    --openapi-url https://api.example.com/openapi.json \\");
        System.out.println("    --api-base-url https://api.example.com");
        System.out.println();
        System.out.println("  java -jar api-security-cli.jar \\");
        System.out.println("    -o https://api.example.com/openapi.json \\");
        System.out.println("    -a https://api.example.com \\");
        System.out.println("    --enable-static-analysis \\");
        System.out.println("    --enable-dynamic-testing");
        System.out.println();
    }
    
    private static class CliArguments {
        String openApiUrl;
        String apiBaseUrl;
        String serverUrl = DEFAULT_SERVER_URL;
        boolean enableStaticAnalysis = false;
        boolean enableDynamicTesting = false;
        boolean enableContractValidation = false;
        boolean enableAiAnalysis = true;
        int timeoutMs = 300000;
        int maxConcurrentRequests = 10;
    }
}

