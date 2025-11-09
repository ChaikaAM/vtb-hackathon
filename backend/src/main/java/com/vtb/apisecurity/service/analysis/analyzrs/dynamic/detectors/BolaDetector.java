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
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
@Component
@AllArgsConstructor
public class BolaDetector {
    
    private final OkHttpClient bankingApiHttpClient;
    private final RateLimiterService rateLimiterService;
    
    private void logHeaders(Request request, String type) {
        log.debug("[BOLA] {} Headers:", type);
        request.headers().forEach(pair -> {
            String headerName = pair.getFirst();
            String headerValue = pair.getSecond();
            // Скрываем токен авторизации для безопасности
            if ("Authorization".equalsIgnoreCase(headerName)) {
                log.debug("[BOLA]   {}: Bearer ***", headerName);
            } else {
                log.debug("[BOLA]   {}: {}", headerName, headerValue);
            }
        });
    }
    
    private void logHeaders(Response response, String type) {
        log.debug("[BOLA] {} Headers:", type);
        response.headers().forEach(pair -> {
            log.debug("[BOLA]   {}: {}", pair.getFirst(), pair.getSecond());
        });
    }
    
    private void logResponseBody(String body, String detector) {
        if (body != null && !body.isEmpty()) {
            // Ограничиваем размер лога до 1000 символов
            String logBody = body.length() > 1000 ? body.substring(0, 1000) + "... (truncated)" : body;
            log.info("[{}] Response Body: {}", detector, logBody);
        } else {
            log.debug("[{}] Response Body: (empty)", detector);
        }
    }
    
    private static final Pattern PATH_PARAM_PATTERN = Pattern.compile("\\{([^}]+)\\}");
    
    public List<Vulnerability> test(String path, String method, String baseUrl, String authToken) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (!path.contains("{")) {
            return vulnerabilities;
        }
        
        try {
            // Extract path parameter name
            Matcher matcher = PATH_PARAM_PATTERN.matcher(path);
            if (!matcher.find()) {
                return vulnerabilities;
            }
            
            String paramName = matcher.group(1);
            
            // Try to access with different IDs
            List<String> testIds = Arrays.asList("1", "2", "999", "0", "-1", "admin", "test");
            
            for (String testId : testIds) {
                String testPath = path.replace("{" + paramName + "}", testId);
                String url = baseUrl + testPath;
                
                Request.Builder requestBuilder = new Request.Builder().url(url);
                
                if (authToken != null && !authToken.isEmpty()) {
                    requestBuilder.header("Authorization", "Bearer " + authToken);
                }
                
                Request request = requestBuilder.build();
                
                // Логирование запроса
                log.info("[BOLA] Request: {} {}", method, url);
                logHeaders(request, "Request");
                
                try {
                    Response response = rateLimiterService.executeWithRateLimit(
                        request,
                        req -> bankingApiHttpClient.newCall(req).execute()
                    );
                    
                    if (response == null) {
                        log.warn("[BOLA] Failed to get response after retries for test ID: {}", testId);
                        continue; // Пропускаем этот тест если не удалось получить ответ
                    }
                    
                    try {
                        // Логирование ответа
                        String responseBody = response.body() != null ? response.body().string() : "";
                        log.info("[BOLA] Response: {} {} - Status: {}", method, url, response.code());
                        logHeaders(response, "Response");
                        logResponseBody(responseBody, "BOLA");
                        
                        // If we get 200 OK for different IDs, it might be BOLA
                        if (response.isSuccessful() && response.code() == 200) {
                            
                            // Check if response contains data (not empty or error)
                            if (!responseBody.isEmpty() && !responseBody.contains("error") && 
                                !responseBody.contains("not found") && !responseBody.contains("404")) {
                                
                                vulnerabilities.add(Vulnerability.builder()
                                        .id(UUID.randomUUID().toString())
                                        .owaspCategory("API1:2023")
                                        .title("Potential Broken Object Level Authorization")
                                        .description("Endpoint " + path + " may allow access to objects without proper authorization. " +
                                                "Successfully accessed resource with ID: " + testId)
                                        .severity(Vulnerability.Severity.HIGH)
                                        .endpoint(path)
                                        .method(method)
                                        .parameter(paramName)
                                        .evidence("Accessed resource with ID: " + testId + " returned 200 OK")
                                        .recommendation("Implement proper authorization checks that verify the user has permission to access the requested object")
                                        .build());
                                
                                // Only report once per endpoint
                                break;
                            }
                        }
                    } finally {
                        response.close();
                    }
                } catch (IOException e) {
                    log.error("[BOLA] Error testing BOLA for {}: {}", url, e.getMessage(), e);
                }
            }
        } catch (Exception e) {
            log.error("Error in BOLA detection for {}: {}", path, e.getMessage(), e);
        }
        
        return vulnerabilities;
    }
}

