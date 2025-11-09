package com.vtb.apisecurity.service.analysis.analyzrs.dynamic.detectors;

import com.vtb.apisecurity.model.Vulnerability;
import com.vtb.apisecurity.service.rate.RateLimiterService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

@Slf4j
@Component
@AllArgsConstructor
public class BusinessFlowDetector {
    
    private final OkHttpClient bankingApiHttpClient;
    private final RateLimiterService rateLimiterService;
    private static final int AUTOMATION_TEST_COUNT = 10;
    private static final List<String> BUSINESS_ENDPOINTS = Arrays.asList(
        "payment", "transfer", "purchase", "order", "product-agreement"
    );
    
    private void logHeaders(Request request, String type) {
        log.debug("[BUSINESS_FLOW] {} Headers:", type);
        request.headers().forEach(pair -> {
            String headerName = pair.getFirst();
            if ("Authorization".equalsIgnoreCase(headerName)) {
                log.debug("[BUSINESS_FLOW]   {}: Bearer ***", headerName);
            } else {
                log.debug("[BUSINESS_FLOW]   {}: {}", headerName, pair.getSecond());
            }
        });
    }
    
    private void logHeaders(Response response, String type) {
        log.debug("[BUSINESS_FLOW] {} Headers:", type);
        response.headers().forEach(pair -> {
            log.debug("[BUSINESS_FLOW]   {}: {}", pair.getFirst(), pair.getSecond());
        });
    }
    
    private void logRequest(Request request, String method, String body, int requestNumber) {
        log.info("[BUSINESS_FLOW] Request #{}/{}: {} {}", requestNumber, AUTOMATION_TEST_COUNT, method, request.url());
        logHeaders(request, "Request");
        if (body != null) {
            String logBody = body.length() > 500 ? body.substring(0, 500) + "... (truncated)" : body;
            log.info("[BUSINESS_FLOW] Request Body: {}", logBody);
        }
    }
    
    private void logResponse(Response response, String method, String url, String responseBody, int requestNumber) {
        log.info("[BUSINESS_FLOW] Response #{}/{}: {} {} - Status: {}", requestNumber, AUTOMATION_TEST_COUNT, method, url, response.code());
        logHeaders(response, "Response");
        if (responseBody != null && !responseBody.isEmpty()) {
            String logBody = responseBody.length() > 1000 ? responseBody.substring(0, 1000) + "... (truncated)" : responseBody;
            log.info("[BUSINESS_FLOW] Response Body: {}", logBody);
        } else {
            log.debug("[BUSINESS_FLOW] Response Body: (empty)");
        }
    }
    
    public List<Vulnerability> test(String path, String method, String baseUrl, String authToken) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Check if this is a business-sensitive endpoint
        String lowerPath = path.toLowerCase();
        boolean isBusinessEndpoint = BUSINESS_ENDPOINTS.stream()
                .anyMatch(lowerPath::contains);
        
        if (!isBusinessEndpoint || !method.equals("POST")) {
            return vulnerabilities;
        }
        
        try {
            String url = baseUrl + path;
            int successCount = 0;
            long startTime = System.currentTimeMillis();
            
            // Try to execute the same business operation multiple times rapidly
            for (int i = 0; i < AUTOMATION_TEST_COUNT; i++) {
                Request.Builder requestBuilder = new Request.Builder().url(url);
                
                if (authToken != null && !authToken.isEmpty()) {
                    requestBuilder.header("Authorization", "Bearer " + authToken);
                }
                
                // Create minimal valid request body
                String bodyContent = "{}";
                RequestBody body = RequestBody.create(bodyContent, MediaType.get("application/json"));
                requestBuilder.post(body);
                
                Request request = requestBuilder.build();
                
                // Логирование запроса
                logRequest(request, method, bodyContent, i + 1);
                
                try {
                    Response response = rateLimiterService.executeWithRateLimit(
                        request,
                        req -> bankingApiHttpClient.newCall(req).execute()
                    );
                    
                    if (response == null) {
                        log.warn("[BUSINESS_FLOW] Failed to get response after retries for request #{}", i + 1);
                        continue; // Пропускаем этот запрос если не удалось получить ответ
                    }
                    
                    try {
                        String responseBody = response.body() != null ? response.body().string() : "";
                        
                        // Логирование ответа
                        logResponse(response, method, url, responseBody, i + 1);
                        
                        // Check if business operation was accepted (not blocked)
                        if (response.code() != 429 && response.code() != 403) {
                            successCount++;
                        }
                        
                        // Check for CAPTCHA or automation detection
                        if (responseBody.toLowerCase().contains("captcha") || 
                            responseBody.toLowerCase().contains("bot detected")) {
                            // Endpoint has automation protection
                            return vulnerabilities;
                        }
                    } finally {
                        response.close();
                    }
                } catch (IOException e) {
                    log.error("[BUSINESS_FLOW] Error in business flow test #{}: {}", i + 1, e.getMessage(), e);
                }
            }
            
            long duration = System.currentTimeMillis() - startTime;
            
            // If most operations succeeded without throttling, it's vulnerable
            if (successCount >= AUTOMATION_TEST_COUNT * 0.7) {
                vulnerabilities.add(Vulnerability.builder()
                        .id(UUID.randomUUID().toString())
                        .owaspCategory("API6:2023")
                        .title("Business Flow Can Be Automated")
                        .description("Endpoint " + path + " allows sensitive business operations to be automated. " +
                                "Successfully executed " + successCount + "/" + AUTOMATION_TEST_COUNT + 
                                " operations in " + duration + "ms without protection")
                        .severity(Vulnerability.Severity.HIGH)
                        .endpoint(path)
                        .method(method)
                        .evidence("Executed " + successCount + " business operations rapidly without throttling or CAPTCHA")
                        .recommendation("Implement CAPTCHA for sensitive business flows. " +
                                "Add rate limiting specific to business operations. " +
                                "Implement business logic rules to prevent abuse (e.g., one operation per user per time period)")
                        .build());
            }
        } catch (Exception e) {
            log.error("Error in business flow detection for {}: {}", path, e.getMessage(), e);
        }
        
        return vulnerabilities;
    }
    
}

