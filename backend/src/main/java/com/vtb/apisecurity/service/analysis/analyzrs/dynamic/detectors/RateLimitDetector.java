package com.vtb.apisecurity.service.analysis.analyzrs.dynamic.detectors;

import com.vtb.apisecurity.model.Vulnerability;
import com.vtb.apisecurity.service.rate.RateLimiterService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Slf4j
@Component
@AllArgsConstructor
public class RateLimitDetector {
    
    private final OkHttpClient bankingApiHttpClient;
    private final RateLimiterService rateLimiterService;
    private static final int TEST_REQUESTS = 20;
    private static final int RATE_LIMIT_THRESHOLD = 10; // If more than 10 requests succeed, likely no rate limit
    
    private void logHeaders(Request request, String type) {
        log.debug("[RATE_LIMIT] {} Headers:", type);
        request.headers().forEach(pair -> {
            String headerName = pair.getFirst();
            if ("Authorization".equalsIgnoreCase(headerName)) {
                log.debug("[RATE_LIMIT]   {}: Bearer ***", headerName);
            } else {
                log.debug("[RATE_LIMIT]   {}: {}", headerName, pair.getSecond());
            }
        });
    }
    
    private void logHeaders(Response response, String type) {
        log.debug("[RATE_LIMIT] {} Headers:", type);
        response.headers().forEach(pair -> {
            log.debug("[RATE_LIMIT]   {}: {}", pair.getFirst(), pair.getSecond());
        });
    }
    
    private void logRequest(Request request, String method, int requestNumber) {
        log.info("[RATE_LIMIT] Request #{}/{}: {} {}", requestNumber, TEST_REQUESTS, method, request.url());
        logHeaders(request, "Request");
    }
    
    private void logResponse(Response response, String method, String url, int requestNumber) {
        log.info("[RATE_LIMIT] Response #{}/{}: {} {} - Status: {}", requestNumber, TEST_REQUESTS, method, url, response.code());
        logHeaders(response, "Response");
    }
    
    public List<Vulnerability> test(String path, String method, String baseUrl, String authToken) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        try {
            String url = baseUrl + path;
            int successCount = 0;
            int unauthorizedCount = 0;
            int validationErrorCount = 0;
            final int MAX_UNAUTHORIZED = 3; // Останавливаемся после 3 подряд 401 ошибок
            final int MAX_VALIDATION_ERRORS = 5; // Останавливаемся после 5 подряд 422 ошибок
            
            for (int i = 0; i < TEST_REQUESTS; i++) {
                Request.Builder requestBuilder = new Request.Builder().url(url);
                
                if (authToken != null && !authToken.isEmpty()) {
                    requestBuilder.header("Authorization", "Bearer " + authToken);
                }
                
                // Add method
                RequestBody body = RequestBody.create("", MediaType.get("application/json"));
                switch (method) {
                    case "POST":
                        requestBuilder.post(body);
                        break;
                    case "PUT":
                        requestBuilder.put(body);
                        break;
                    case "DELETE":
                        requestBuilder.delete();
                        break;
                    default:
                        requestBuilder.get();
                }
                
                Request request = requestBuilder.build();
                
                // Логирование запроса
                logRequest(request, method, i + 1);
                
                try {
                    Response response = rateLimiterService.executeWithRateLimit(
                        request,
                        req -> bankingApiHttpClient.newCall(req).execute()
                    );
                    
                    if (response == null) {
                        log.warn("[RATE_LIMIT] Failed to get response after retries for request #{}", i + 1);
                        // Если не удалось получить ответ после всех попыток, считаем что rate limiting есть
                        return vulnerabilities;
                    }
                    
                    try {
                        // Логирование ответа
                        logResponse(response, method, url, i + 1);
                        
                        int statusCode = response.code();
                        
                        // Если получили 401 (Unauthorized) несколько раз подряд - прекращаем тест
                        if (statusCode == 401) {
                            unauthorizedCount++;
                            if (unauthorizedCount >= MAX_UNAUTHORIZED) {
                                log.info("[RATE_LIMIT] Stopping test after {} unauthorized responses (401). Cannot test rate limiting without valid authentication.", unauthorizedCount);
                                return vulnerabilities;
                            }
                            validationErrorCount = 0; // Сбрасываем счетчик валидационных ошибок
                            continue; // Продолжаем, но не считаем как успешный запрос
                        } else {
                            unauthorizedCount = 0; // Сбрасываем счетчик при другом статусе
                        }
                        
                        // Если получили 422 (Unprocessable Entity) несколько раз подряд - прекращаем тест
                        // 422 означает, что запросы проходят валидацию, но данные невалидны
                        // Это не позволяет проверить rate limiting, так как запросы отклоняются до проверки лимитов
                        if (statusCode == 422) {
                            validationErrorCount++;
                            log.debug("[RATE_LIMIT] Got 422 validation error (count: {}/{})", validationErrorCount, MAX_VALIDATION_ERRORS);
                            if (validationErrorCount >= MAX_VALIDATION_ERRORS) {
                                log.info("[RATE_LIMIT] Stopping test after {} validation error responses (422). Cannot reliably test rate limiting with invalid request data.", validationErrorCount);
                                return vulnerabilities;
                            }
                            continue; // Продолжаем, но не считаем как успешный запрос
                        } else {
                            validationErrorCount = 0; // Сбрасываем счетчик при другом статусе
                        }
                        
                        // Check for rate limit headers
                        String rateLimitHeader = response.header("X-RateLimit-Limit");
                        String rateLimitRemaining = response.header("X-RateLimit-Remaining");
                        String retryAfter = response.header("Retry-After");
                        
                        if (rateLimitHeader != null || rateLimitRemaining != null || retryAfter != null) {
                            // Rate limiting is implemented
                            response.close();
                            return vulnerabilities;
                        }
                        
                        // Check for 429 Too Many Requests (должно быть обработано в rateLimiterService)
                        if (statusCode == 429) {
                            // Rate limiting is implemented
                            response.close();
                            return vulnerabilities;
                        }
                        
                        if (response.isSuccessful()) {
                            successCount++;
                        }
                    } finally {
                        response.close();
                    }
                } catch (IOException e) {
                    log.error("[RATE_LIMIT] Error in rate limit test #{}: {}", i + 1, e.getMessage(), e);
                }
            }
            
            // If many requests succeeded without rate limiting, report vulnerability
            if (successCount > RATE_LIMIT_THRESHOLD) {
                vulnerabilities.add(Vulnerability.builder()
                        .id(UUID.randomUUID().toString())
                        .owaspCategory("API4:2023")
                        .title("Missing Rate Limiting")
                        .description("Endpoint " + path + " does not implement rate limiting. " +
                                "Successfully processed " + successCount + " requests without throttling")
                        .severity(Vulnerability.Severity.MEDIUM)
                        .endpoint(path)
                        .method(method)
                        .evidence("Processed " + successCount + "/" + TEST_REQUESTS + " requests without rate limiting")
                        .recommendation("Implement rate limiting on all API endpoints (per user, IP, or API key)")
                        .build());
            }
        } catch (Exception e) {
            log.error("Error in rate limit detection for {}: {}", path, e.getMessage(), e);
        }
        
        return vulnerabilities;
    }
}

