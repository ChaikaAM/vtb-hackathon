package com.vtb.apisecurity.service.analysis.analyzrs;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vtb.apisecurity.model.ContractMismatch;
import com.vtb.apisecurity.service.rate.RateLimiterService;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.responses.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

@Service
@Slf4j
public class ContractValidationService {
    
    private final OkHttpClient httpClient;
    private final RateLimiterService rateLimiterService;
    
    public ContractValidationService(
            @Qualifier("bankingApiHttpClient") OkHttpClient httpClient,
            RateLimiterService rateLimiterService) {
        this.httpClient = httpClient;
        this.rateLimiterService = rateLimiterService;
    }
    
    private void logHeaders(Request request, String type) {
        log.debug("[CONTRACT_VALIDATION] {} Headers:", type);
        request.headers().forEach(pair -> {
            String headerName = pair.getFirst();
            if ("Authorization".equalsIgnoreCase(headerName)) {
                log.debug("[CONTRACT_VALIDATION]   {}: Bearer ***", headerName);
            } else {
                log.debug("[CONTRACT_VALIDATION]   {}: {}", headerName, pair.getSecond());
            }
        });
    }
    
    private void logHeaders(Response response, String type) {
        log.debug("[CONTRACT_VALIDATION] {} Headers:", type);
        response.headers().forEach(pair -> {
            log.debug("[CONTRACT_VALIDATION]   {}: {}", pair.getFirst(), pair.getSecond());
        });
    }
    
    private void logRequest(Request request, String method) {
        log.info("[CONTRACT_VALIDATION] Request: {} {}", method, request.url());
        logHeaders(request, "Request");
    }
    
    private void logResponse(Response response, String method, String url, String responseBody) {
        log.info("[CONTRACT_VALIDATION] Response: {} {} - Status: {}", method, url, response.code());
        logHeaders(response, "Response");
        if (responseBody != null && !responseBody.isEmpty()) {
            String logBody = responseBody.length() > 1000 ? responseBody.substring(0, 1000) + "... (truncated)" : responseBody;
            log.info("[CONTRACT_VALIDATION] Response Body: {}", logBody);
        } else {
            log.debug("[CONTRACT_VALIDATION] Response Body: (empty)");
        }
    }
    
    public List<ContractMismatch> validate(OpenAPI openAPI, String apiBaseUrl, String authToken) {
        log.info("Starting contract validation");
        List<ContractMismatch> mismatches = new ArrayList<>();
        
        if (openAPI.getPaths() == null) {
            return mismatches;
        }
        
        String baseUrl = apiBaseUrl.endsWith("/") ? apiBaseUrl.substring(0, apiBaseUrl.length() - 1) : apiBaseUrl;
        
        openAPI.getPaths().forEach((path, pathItem) -> {
            try {
                List<ContractMismatch> pathMismatches = validatePath(path, pathItem, baseUrl, authToken, openAPI);
                mismatches.addAll(pathMismatches);
            } catch (Exception e) {
                log.error("Error validating path {}: {}", path, e.getMessage(), e);
            }
        });
        
        log.info("Contract validation completed. Found {} mismatches", mismatches.size());
        return mismatches;
    }
    
    private List<ContractMismatch> validatePath(String path, PathItem pathItem, String baseUrl, 
                                                String authToken, OpenAPI openAPI) {
        List<ContractMismatch> mismatches = new ArrayList<>();
        
        // Skip paths with parameters for now (would need actual values)
        if (path.contains("{")) {
            return mismatches;
        }
        
        // Test GET endpoints
        if (pathItem.getGet() != null) {
            mismatches.addAll(validateOperation(path, "GET", pathItem.getGet(), baseUrl, authToken, openAPI));
        }
        
        return mismatches;
    }
    
    private List<ContractMismatch> validateOperation(String path, String method, Operation operation, 
                                                     String baseUrl, String authToken, OpenAPI openAPI) {
        List<ContractMismatch> mismatches = new ArrayList<>();
        
        try {
            String url = baseUrl + path;
            Request.Builder requestBuilder = new Request.Builder().url(url);
            
            if (authToken != null && !authToken.isEmpty()) {
                requestBuilder.header("Authorization", "Bearer " + authToken);
            }
            
            Request request = requestBuilder.build();
            
            // Логирование запроса
            logRequest(request, method);
            
            Response response = rateLimiterService.executeWithRateLimit(
                request,
                req -> httpClient.newCall(req).execute()
            );
            
            if (response == null) {
                log.warn("[CONTRACT_VALIDATION] Failed to get response after retries for {} {}", method, path);
                return mismatches;
            }
            
            try {
                int statusCode = response.code();
                
                // Получаем тело ответа для логирования
                String responseBody = response.body() != null ? response.body().string() : "";
                
                // Логирование ответа
                logResponse(response, method, url, responseBody);
                
                // Check status code
                ApiResponse expectedResponse = operation.getResponses().get(String.valueOf(statusCode));
                if (expectedResponse == null) {
                    // Check for default responses
                    expectedResponse = operation.getResponses().get("default");
                    if (expectedResponse == null && statusCode >= 200 && statusCode < 300) {
                        expectedResponse = operation.getResponses().get("200");
                    }
                }
                
                if (expectedResponse == null) {
                    mismatches.add(ContractMismatch.builder()
                            .endpoint(path)
                            .method(method)
                            .type("STATUS_CODE")
                            .expected("200, 201, 400, 401, 403, 404, 500")
                            .actual(String.valueOf(statusCode))
                            .message("Unexpected status code: " + statusCode)
                            .severity(com.vtb.apisecurity.model.Vulnerability.Severity.MEDIUM)
                            .build());
                }
                
                // Validate response schema if available
                if (expectedResponse != null && expectedResponse.getContent() != null) {
                    MediaType mediaType = expectedResponse.getContent().get("application/json");
                    if (mediaType != null && mediaType.getSchema() != null && !responseBody.isEmpty()) {
                        try {
                            validateSchema(responseBody, mediaType.getSchema(), mismatches, path, method);
                        } catch (Exception e) {
                            log.debug("Error validating schema for {}: {}", path, e.getMessage());
                        }
                    }
                }
            } finally {
                response.close();
            }
        } catch (IOException e) {
            log.error("[CONTRACT_VALIDATION] Error validating operation {} {}: {}", method, path, e.getMessage(), e);
        }
        
        return mismatches;
    }
    
    private void validateSchema(String responseBody, io.swagger.v3.oas.models.media.Schema<?> schema, 
                                List<ContractMismatch> mismatches, String path, String method) {
        try {
            // Parse response as JSON
            ObjectMapper mapper = new ObjectMapper();
            JsonNode jsonResponse = mapper.readTree(responseBody);
            
            // Basic type checking
            String expectedType = schema.getType();
            if (expectedType != null) {
                if (expectedType.equals("object") && !jsonResponse.isObject()) {
                    mismatches.add(ContractMismatch.builder()
                            .endpoint(path)
                            .method(method)
                            .type("SCHEMA")
                            .expected("object")
                            .actual(jsonResponse.getNodeType().toString())
                            .message("Response type mismatch")
                            .severity(com.vtb.apisecurity.model.Vulnerability.Severity.MEDIUM)
                            .build());
                } else if (expectedType.equals("array") && !jsonResponse.isArray()) {
                    mismatches.add(ContractMismatch.builder()
                            .endpoint(path)
                            .method(method)
                            .type("SCHEMA")
                            .expected("array")
                            .actual(jsonResponse.getNodeType().toString())
                            .message("Response type mismatch")
                            .severity(com.vtb.apisecurity.model.Vulnerability.Severity.MEDIUM)
                            .build());
                }
            }
        } catch (Exception e) {
            log.debug("Error in schema validation: {}", e.getMessage());
        }
    }
}

