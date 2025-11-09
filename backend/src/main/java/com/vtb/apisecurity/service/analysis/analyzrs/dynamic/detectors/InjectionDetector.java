package com.vtb.apisecurity.service.analysis.analyzrs.dynamic.detectors;

import com.vtb.apisecurity.model.Vulnerability;
import com.vtb.apisecurity.service.analysis.analyzrs.dynamic.payload.PayloadGenerator;
import com.vtb.apisecurity.service.rate.RateLimiterService;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.parameters.Parameter;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

@Slf4j
@Component
@AllArgsConstructor
public class InjectionDetector {

    private final OkHttpClient bankingApiHttpClient;
    private final PayloadGenerator payloadGenerator;
    private final RateLimiterService rateLimiterService;
    
    private void logHeaders(Request request, String type) {
        log.debug("[INJECTION] {} Headers:", type);
        request.headers().forEach(pair -> {
            String headerName = pair.getFirst();
            String headerValue = pair.getSecond();
            if ("Authorization".equalsIgnoreCase(headerName)) {
                log.debug("[INJECTION]   {}: Bearer ***", headerName);
            } else {
                log.debug("[INJECTION]   {}: {}", headerName, headerValue);
            }
        });
    }
    
    private void logHeaders(Response response, String type) {
        log.debug("[INJECTION] {} Headers:", type);
        response.headers().forEach(pair -> {
            log.debug("[INJECTION]   {}: {}", pair.getFirst(), pair.getSecond());
        });
    }
    
    private void logRequest(Request request, String method, String payload) {
        log.info("[INJECTION] Request: {} {}", method, request.url());
        logHeaders(request, "Request");
        if (payload != null) {
            log.info("[INJECTION] Payload: {}", payload);
        }
    }
    
    private void logResponse(Response response, String method, String url, String responseBody) {
        log.info("[INJECTION] Response: {} {} - Status: {}", method, url, response.code());
        logHeaders(response, "Response");
        if (responseBody != null && !responseBody.isEmpty()) {
            String logBody = responseBody.length() > 1000 ? responseBody.substring(0, 1000) + "... (truncated)" : responseBody;
            log.info("[INJECTION] Response Body: {}", logBody);
        } else {
            log.debug("[INJECTION] Response Body: (empty)");
        }
    }

    private static final Pattern SQL_ERROR_PATTERN = Pattern.compile(
        "(?i)(sql syntax|mysql_fetch|postgresql|oracle error|sqlite|sql server|odbc|jdbc|database error)"
    );

    public List<Vulnerability> test(String path, Operation operation, String baseUrl, String authToken) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        if (operation.getParameters() == null) {
            return vulnerabilities;
        }

        String method = getMethod(operation);

        for (Parameter param : operation.getParameters()) {
            if (param.getIn().equals("query") || param.getIn().equals("path")) {
                // Test SQL injection
                vulnerabilities.addAll(testSqlInjection(path, method, param, baseUrl, authToken));

                // Test XSS
                vulnerabilities.addAll(testXss(path, method, param, baseUrl, authToken));
            }
        }

        return vulnerabilities;
    }

    private List<Vulnerability> testSqlInjection(String path, String method, Parameter param,
                                                 String baseUrl, String authToken) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (String payload : payloadGenerator.generateSqlInjectionPayloads()) {
            try {
                String url = buildUrl(baseUrl, path, param, payload);
                Request.Builder requestBuilder = new Request.Builder().url(url);

                if (authToken != null && !authToken.isEmpty()) {
                    requestBuilder.header("Authorization", "Bearer " + authToken);
                }

                Request request = requestBuilder.build();
                
                // Логирование запроса
                logRequest(request, method, payload);

                Response response = rateLimiterService.executeWithRateLimit(
                    request,
                    req -> bankingApiHttpClient.newCall(req).execute()
                );
                
                if (response == null) {
                    log.warn("[INJECTION] Failed to get response after retries for SQL injection test");
                    continue; // Пропускаем этот payload если не удалось получить ответ
                }
                
                try {
                    String responseBody = response.body() != null ? response.body().string() : "";
                    
                    // Логирование ответа
                    logResponse(response, method, url, responseBody);

                    if (SQL_ERROR_PATTERN.matcher(responseBody).find()) {
                        vulnerabilities.add(Vulnerability.builder()
                            .id(UUID.randomUUID().toString())
                            .owaspCategory("API8:2023")
                            .title("SQL Injection Vulnerability")
                            .description("Parameter '" + param.getName() + "' in " + path +
                                " appears to be vulnerable to SQL injection")
                            .severity(Vulnerability.Severity.CRITICAL)
                            .endpoint(path)
                            .method(method)
                            .parameter(param.getName())
                            .evidence("SQL error detected in response: " + extractError(responseBody))
                            .recommendation("Use parameterized queries or prepared statements. Never concatenate user" +
                                " input into SQL queries")
                            .build());
                        break; // Found vulnerability, no need to test more payloads
                    }
                } finally {
                    response.close();
                }
            } catch (IOException e) {
                log.error("[INJECTION] Error testing SQL injection for {}: {}", path, e.getMessage(), e);
            }
        }

        return vulnerabilities;
    }

    private List<Vulnerability> testXss(String path, String method, Parameter param,
                                        String baseUrl, String authToken) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (String payload : payloadGenerator.generateXssPayloads()) {
            try {
                String url = buildUrl(baseUrl, path, param, payload);
                Request.Builder requestBuilder = new Request.Builder().url(url);

                if (authToken != null && !authToken.isEmpty()) {
                    requestBuilder.header("Authorization", "Bearer " + authToken);
                }

                Request request = requestBuilder.build();
                
                // Логирование запроса
                logRequest(request, method, payload);

                Response response = rateLimiterService.executeWithRateLimit(
                    request,
                    req -> bankingApiHttpClient.newCall(req).execute()
                );
                
                if (response == null) {
                    log.warn("[INJECTION] Failed to get response after retries for XSS test");
                    continue; // Пропускаем этот payload если не удалось получить ответ
                }
                
                try {
                    String responseBody = response.body() != null ? response.body().string() : "";
                    
                    // Логирование ответа
                    logResponse(response, method, url, responseBody);

                    // Check if payload is reflected in response
                    if (responseBody.contains(payload)) {
                        vulnerabilities.add(Vulnerability.builder()
                            .id(UUID.randomUUID().toString())
                            .owaspCategory("API8:2023")
                            .title("Cross-Site Scripting (XSS) Vulnerability")
                            .description("Parameter '" + param.getName() + "' in " + path +
                                " reflects user input without proper encoding")
                            .severity(Vulnerability.Severity.HIGH)
                            .endpoint(path)
                            .method(method)
                            .parameter(param.getName())
                            .evidence("XSS payload reflected in response")
                            .recommendation("Encode all user input before outputting it. Use context-appropriate " +
                                "encoding (HTML, JavaScript, URL)")
                            .build());
                        break;
                    }
                } finally {
                    response.close();
                }
            } catch (IOException e) {
                log.error("[INJECTION] Error testing XSS for {}: {}", path, e.getMessage(), e);
            }
        }

        return vulnerabilities;
    }

    private String buildUrl(String baseUrl, String path, Parameter param, String value) {
        String normalizedPath = path.replaceAll("\\{[^}]+\\}", value);
        String url = baseUrl + normalizedPath;

        if (param.getIn().equals("query")) {
            url += (url.contains("?") ? "&" : "?") + param.getName() + "=" + value;
        }

        return url;
    }

    private String extractError(String responseBody) {
        // Extract first line of error message
        String[] lines = responseBody.split("\n");
        return lines.length > 0 ? lines[0].substring(0, Math.min(200, lines[0].length())) : responseBody.substring(0,
            Math.min(200, responseBody.length()));
    }

    private String getMethod(Operation operation) {
        // This is a simplified version - in real implementation, we'd track the method
        return "GET";
    }
}

