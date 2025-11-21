package com.vtb.apisecurity.service.analysis.entity;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vtb.apisecurity.model.ContractMismatch;
import com.vtb.apisecurity.model.Vulnerability;
import com.vtb.apisecurity.model.entity.GeneratedRequest;
import com.vtb.apisecurity.service.ai.AiAgentService;
import com.vtb.apisecurity.service.rate.RateLimiterService;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.responses.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

@Service
@Slf4j
public class AiContractValidationService {
    
    private final OkHttpClient httpClient;
    private final RateLimiterService rateLimiterService;
    private final AiAgentService aiAgentService;
    private final AiRequestGeneratorService requestGeneratorService;
    private final EntityOperationExtractor operationExtractor;
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    public AiContractValidationService(
            @Qualifier("bankingApiHttpClient") OkHttpClient httpClient,
            RateLimiterService rateLimiterService,
            AiAgentService aiAgentService,
            AiRequestGeneratorService requestGeneratorService,
            EntityOperationExtractor operationExtractor) {
        this.httpClient = httpClient;
        this.rateLimiterService = rateLimiterService;
        this.aiAgentService = aiAgentService;
        this.requestGeneratorService = requestGeneratorService;
        this.operationExtractor = operationExtractor;
    }
    
    /**
     * Валидирует все эндпоинты с использованием сгенерированных ИИ запросов
     * ВАЖНО: Сначала выполняются POST методы с consents (согласия), 
     * так как без них другие методы будут возвращать ошибки
     */
    public List<ContractMismatch> validateWithAiGeneratedRequests(
            OpenAPI openAPI, 
            String apiBaseUrl, 
            String authToken) {
        
        log.info("Starting AI-enhanced contract validation");
        List<ContractMismatch> mismatches = new ArrayList<>();
        
        if (openAPI.getPaths() == null) {
            return mismatches;
        }
        
        String baseUrl = apiBaseUrl.endsWith("/") ? 
            apiBaseUrl.substring(0, apiBaseUrl.length() - 1) : apiBaseUrl;
        
        // Собрать все пути и отсортировать их
        // Приоритет: 
        // 1. POST методы с "consents" - первыми (создание согласий)
        // 2. Остальные consents (GET, PUT, PATCH) - после POST consents
        // 3. Обычные пути (не-consents) - после consents
        // 4. DELETE методы с "consents" - В САМОМ КОНЦЕ (удаление согласий)
        List<Map.Entry<String, PathItem>> sortedPaths = new ArrayList<>(openAPI.getPaths().entrySet());
        sortedPaths.sort((entry1, entry2) -> {
            String path1 = entry1.getKey();
            String path2 = entry2.getKey();
            PathItem pathItem1 = entry1.getValue();
            PathItem pathItem2 = entry2.getValue();
            
            boolean isConsent1 = path1.toLowerCase().contains("consent");
            boolean isConsent2 = path2.toLowerCase().contains("consent");
            boolean hasPost1 = pathItem1.getPost() != null;
            boolean hasPost2 = pathItem2.getPost() != null;
            boolean hasDelete1 = pathItem1.getDelete() != null;
            boolean hasDelete2 = pathItem2.getDelete() != null;
            
            // DELETE consents идут В САМОМ КОНЦЕ - после всех остальных путей
            if (isConsent1 && hasDelete1 && !(isConsent2 && hasDelete2)) {
                return 1; // path1 с DELETE consent идет после всех
            }
            if (isConsent2 && hasDelete2 && !(isConsent1 && hasDelete1)) {
                return -1; // path2 с DELETE consent идет после всех
            }
            
            // Оба пути с DELETE consent - равны между собой
            if (isConsent1 && hasDelete1 && isConsent2 && hasDelete2) {
                return 0;
            }
            
            // POST consents идут первыми
            if (isConsent1 && hasPost1 && !(isConsent2 && hasPost2)) {
                return -1;
            }
            if (isConsent2 && hasPost2 && !(isConsent1 && hasPost1)) {
                return 1;
            }
            
            // Остальные consents (GET, PUT, PATCH) идут перед обычными путями
            if (isConsent1 && !isConsent2) {
                return -1;
            }
            if (isConsent2 && !isConsent1) {
                return 1;
            }
            
            return 0;
        });
        
        log.info("Processing {} paths. Order: POST consents → other consents → regular paths → DELETE consents", sortedPaths.size());
        
        // Логирование порядка для отладки
        if (log.isDebugEnabled()) {
            log.debug("Execution order:");
            for (int i = 0; i < sortedPaths.size(); i++) {
                String path = sortedPaths.get(i).getKey();
                PathItem item = sortedPaths.get(i).getValue();
                List<String> methods = new ArrayList<>();
                if (item.getPost() != null) methods.add("POST");
                if (item.getGet() != null) methods.add("GET");
                if (item.getPut() != null) methods.add("PUT");
                if (item.getPatch() != null) methods.add("PATCH");
                if (item.getDelete() != null) methods.add("DELETE");
                log.debug("  {}. {} [{}]", i + 1, path, String.join(", ", methods));
            }
        }
        
        // Для каждого пути (в отсортированном порядке)
        for (Map.Entry<String, PathItem> entry : sortedPaths) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            try {
                List<ContractMismatch> pathMismatches = validatePath(
                    path, pathItem, baseUrl, authToken, openAPI);
                mismatches.addAll(pathMismatches);
            } catch (Exception e) {
                log.error("Error validating path {}: {}", path, e.getMessage(), e);
            }
        }
        
        log.info("AI-enhanced contract validation completed. Found {} mismatches", mismatches.size());
        return mismatches;
    }
    
    /**
     * Валидирует путь (все методы)
     * Сортирует запросы так, чтобы POST методы выполнялись первыми
     */
    private List<ContractMismatch> validatePath(
            String path, 
            PathItem pathItem, 
            String baseUrl, 
            String authToken, 
            OpenAPI openAPI) {
        
        List<ContractMismatch> mismatches = new ArrayList<>();
        
        // Получить имя сущности из пути
        String entityName = extractEntityFromPath(path);
        
        // Извлечь операции
        List<com.vtb.apisecurity.model.entity.EntityOperation> operations = 
            operationExtractor.extractEntityOperations(openAPI, entityName != null ? entityName : "unknown");
        
        // Отфильтровать операции для данного пути
        operations = operations.stream()
            .filter(op -> op.getPath().equals(path))
            .toList();
        
        if (operations.isEmpty()) {
            return mismatches;
        }
        
        // Сгенерировать запросы с помощью ИИ
        List<GeneratedRequest> requests = requestGeneratorService.generateRequestsForEntity(
            operations, openAPI, entityName != null ? entityName : "unknown", authToken);
        
        // Отсортировать запросы: POST первыми, DELETE последними
        boolean isConsentPath = path.toLowerCase().contains("consent");
        
        requests.sort((req1, req2) -> {
            String method1 = req1.getMethod();
            String method2 = req2.getMethod();
            
            // Для consent путей: DELETE в конец
            if (isConsentPath) {
                if ("DELETE".equals(method1) && !"DELETE".equals(method2)) {
                    return 1; // DELETE идет после всех
                }
                if ("DELETE".equals(method2) && !"DELETE".equals(method1)) {
                    return -1; // DELETE идет после всех
                }
            }
            
            // POST идут первыми
            if ("POST".equals(method1) && !"POST".equals(method2)) {
                return -1;
            }
            if ("POST".equals(method2) && !"POST".equals(method1)) {
                return 1;
            }
            
            return 0;
        });
        
        if (isConsentPath) {
            boolean hasPost = requests.stream().anyMatch(r -> "POST".equals(r.getMethod()));
            boolean hasDelete = requests.stream().anyMatch(r -> "DELETE".equals(r.getMethod()));
            
            if (hasPost || hasDelete) {
                log.info("Processing CONSENT path {} - POST first, DELETE last", path);
            }
        }
        
        // Выполнить каждый запрос и валидировать (в отсортированном порядке)
        for (GeneratedRequest generatedRequest : requests) {
            try {
                List<ContractMismatch> requestMismatches = executeAndValidate(
                    generatedRequest, baseUrl, authToken, openAPI, pathItem);
                mismatches.addAll(requestMismatches);
            } catch (Exception e) {
                log.error("Error executing request {} {}: {}", 
                    generatedRequest.getMethod(), generatedRequest.getPath(), e.getMessage(), e);
            }
        }
        
        return mismatches;
    }
    
    /**
     * Выполняет запрос и валидирует ответ с помощью ИИ
     */
    private List<ContractMismatch> executeAndValidate(
            GeneratedRequest generatedRequest,
            String baseUrl,
            String authToken,
            OpenAPI openAPI,
            PathItem pathItem) throws IOException {
        
        List<ContractMismatch> mismatches = new ArrayList<>();
        
        // Построить URL
        String url = generatedRequest.buildUrl(baseUrl);
        
        // Построить Request
        Request.Builder requestBuilder = new Request.Builder().url(url);
        
        // Добавить headers
        if (generatedRequest.getHeaders() != null) {
            generatedRequest.getHeaders().forEach((name, value) -> {
                // Заменить <token> на реальный токен
                if (value != null && value.contains("<token>") && authToken != null) {
                    value = value.replace("<token>", authToken);
                }
                requestBuilder.header(name, value != null ? value : "");
            });
        }
        
        // Добавить Authorization если не был добавлен
        if (authToken != null && !authToken.isEmpty() && 
            (generatedRequest.getHeaders() == null || !generatedRequest.getHeaders().containsKey("Authorization"))) {
            requestBuilder.header("Authorization", "Bearer " + authToken);
        }
        
        // Добавить body для POST/PUT/PATCH
        if (Arrays.asList("POST", "PUT", "PATCH").contains(generatedRequest.getMethod()) && 
            generatedRequest.getBody() != null) {
            String bodyJson = objectMapper.writeValueAsString(generatedRequest.getBody());
            requestBuilder.method(generatedRequest.getMethod(), 
                RequestBody.create(bodyJson, MediaType.get("application/json")));
        } else {
            requestBuilder.method(generatedRequest.getMethod(), 
                generatedRequest.getMethod().equals("GET") || generatedRequest.getMethod().equals("DELETE") 
                    ? null 
                    : RequestBody.create("", MediaType.get("application/json")));
        }
        
        Request request = requestBuilder.build();
        
        log.info("=".repeat(80));
        log.info("[AI_CONTRACT] Executing generated request");
        log.info("[AI_CONTRACT] Method: {}", generatedRequest.getMethod());
        log.info("[AI_CONTRACT] URL: {}", url);
        log.info("[AI_CONTRACT] Headers:");
        request.headers().forEach(pair -> {
            String headerName = pair.getFirst();
            String headerValue = pair.getSecond();
            if ("Authorization".equalsIgnoreCase(headerName)) {
                log.info("[AI_CONTRACT]   {}: Bearer ***", headerName);
            } else {
                log.info("[AI_CONTRACT]   {}: {}", headerName, headerValue);
            }
        });
        
        if (generatedRequest.getBody() != null) {
            try {
                String bodyJson = objectMapper.writerWithDefaultPrettyPrinter()
                    .writeValueAsString(generatedRequest.getBody());
                log.info("[AI_CONTRACT] Request Body:");
                log.info("{}", bodyJson);
            } catch (Exception e) {
                log.info("[AI_CONTRACT] Request Body: {}", generatedRequest.getBody());
            }
        } else {
            log.info("[AI_CONTRACT] Request Body: null");
        }
        log.info("─".repeat(80));
        
        // Выполнить запрос
        log.info("[AI_CONTRACT] Sending HTTP request...");
        Response response = rateLimiterService.executeWithRateLimit(
            request,
            req -> httpClient.newCall(req).execute()
        );
        
        if (response == null) {
            log.warn("[AI_CONTRACT] Failed to get response after retries for {} {}", 
                generatedRequest.getMethod(), generatedRequest.getPath());
            return mismatches;
        }
        
        try {
            int statusCode = response.code();
            String responseBody = response.body() != null ? response.body().string() : "";
            
            log.info("[AI_CONTRACT] Response received:");
            log.info("[AI_CONTRACT] Status: {}", statusCode);
            log.info("[AI_CONTRACT] Response Headers:");
            response.headers().forEach(pair -> {
                log.info("[AI_CONTRACT]   {}: {}", pair.getFirst(), pair.getSecond());
            });
            
            if (responseBody != null && !responseBody.isEmpty()) {
                try {
                    Object json = objectMapper.readValue(responseBody, Object.class);
                    String prettyJson = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(json);
                    log.info("[AI_CONTRACT] Response Body:");
                    if (prettyJson.length() > 2000) {
                        log.info("{}\n... (truncated, total length: {} chars)", 
                            prettyJson.substring(0, 2000), prettyJson.length());
                    } else {
                        log.info("{}", prettyJson);
                    }
                } catch (Exception e) {
                    if (responseBody.length() > 1000) {
                        log.info("[AI_CONTRACT] Response Body: {}\n... (truncated)", 
                            responseBody.substring(0, 1000));
                    } else {
                        log.info("[AI_CONTRACT] Response Body: {}", responseBody);
                    }
                }
            } else {
                log.info("[AI_CONTRACT] Response Body: (empty)");
            }
            log.info("─".repeat(80));
            
            // Получить ожидаемые ответы из операции
            Operation operation = getOperation(pathItem, generatedRequest.getMethod());
            if (operation == null) {
                return mismatches;
            }
            
            // Собрать ожидаемые статус-коды
            String expectedStatusCodes = operation.getResponses() != null ? 
                String.join(", ", operation.getResponses().keySet()) : "200";
            
            // Получить схему ожидаемого ответа
            String expectedSchema = extractExpectedSchema(operation, statusCode);
            
            // Валидация через ИИ
            log.info("[AI_CONTRACT] Validating response with AI...");
            log.info("[AI_CONTRACT] Expected status codes: {}", expectedStatusCodes);
            log.info("[AI_CONTRACT] Expected schema length: {} chars", expectedSchema.length());
            
            String aiValidationResult = aiAgentService.validateResponseAgainstSpec(
                buildOperationDescription(generatedRequest, operation),
                expectedSchema,
                responseBody,
                statusCode,
                expectedStatusCodes
            );
            
            if (aiValidationResult != null) {
                log.info("[AI_CONTRACT] AI Validation Result:");
                log.info("─".repeat(80));
                log.info("{}", aiValidationResult);
                log.info("─".repeat(80));
            }
            
            if (aiValidationResult != null) {
                // Парсить результат валидации
                mismatches.addAll(parseValidationResult(
                    aiValidationResult, 
                    generatedRequest.getPath(), 
                    generatedRequest.getMethod()));
            }
            
        } finally {
            response.close();
        }
        
        return mismatches;
    }
    
    private Operation getOperation(PathItem pathItem, String method) {
        return switch (method.toUpperCase()) {
            case "GET" -> pathItem.getGet();
            case "POST" -> pathItem.getPost();
            case "PUT" -> pathItem.getPut();
            case "PATCH" -> pathItem.getPatch();
            case "DELETE" -> pathItem.getDelete();
            default -> null;
        };
    }
    
    private String buildOperationDescription(GeneratedRequest request, Operation operation) {
        StringBuilder desc = new StringBuilder();
        desc.append(request.getMethod()).append(" ").append(request.getPath()).append("\n");
        if (operation.getSummary() != null) {
            desc.append(operation.getSummary()).append("\n");
        }
        if (request.getDescription() != null) {
            desc.append(request.getDescription());
        }
        return desc.toString();
    }
    
    private String extractExpectedSchema(Operation operation, int statusCode) {
        if (operation.getResponses() == null) {
            return "{}";
        }
        
        // Попытаться найти схему для статус-кода
        ApiResponse apiResponse = operation.getResponses().get(String.valueOf(statusCode));
        if (apiResponse == null) {
            apiResponse = operation.getResponses().get("default");
        }
        if (apiResponse == null && statusCode >= 200 && statusCode < 300) {
            apiResponse = operation.getResponses().get("200");
        }
        
        if (apiResponse != null && apiResponse.getContent() != null) {
            io.swagger.v3.oas.models.media.MediaType mediaType = 
                apiResponse.getContent().get("application/json");
            if (mediaType != null && mediaType.getSchema() != null) {
                try {
                    return objectMapper.writerWithDefaultPrettyPrinter()
                        .writeValueAsString(mediaType.getSchema());
                } catch (Exception e) {
                    log.debug("Error serializing schema: {}", e.getMessage());
                }
            }
        }
        
        return "{}";
    }
    
    /**
     * Парсит результат валидации от ИИ
     */
    private List<ContractMismatch> parseValidationResult(
            String aiValidationResult, 
            String path, 
            String method) {
        
        List<ContractMismatch> mismatches = new ArrayList<>();
        
        try {
            // Извлечь JSON из ответа
            String cleanJson = extractJsonFromResponse(aiValidationResult);
            
            @SuppressWarnings("unchecked")
            Map<String, Object> result = objectMapper.readValue(cleanJson, Map.class);
            
            Boolean isValid = (Boolean) result.get("isValid");
            
            if (isValid != null && !isValid) {
                // Статус-код не соответствует
                Boolean statusCodeMatch = (Boolean) result.get("statusCodeMatch");
                if (statusCodeMatch != null && !statusCodeMatch) {
                    mismatches.add(ContractMismatch.builder()
                        .endpoint(path)
                        .method(method)
                        .type("STATUS_CODE")
                        .expected("As per OpenAPI spec")
                        .actual("Different status code")
                        .message("Status code mismatch detected by AI")
                        .severity(Vulnerability.Severity.MEDIUM)
                        .build());
                }
                
                // Схема не соответствует
                Boolean schemaMatch = (Boolean) result.get("schemaMatch");
                if (schemaMatch != null && !schemaMatch) {
                    @SuppressWarnings("unchecked")
                    List<String> issues = (List<String>) result.get("issues");
                    String issuesStr = issues != null ? String.join("; ", issues) : "Schema mismatch";
                    
                    mismatches.add(ContractMismatch.builder()
                        .endpoint(path)
                        .method(method)
                        .type("SCHEMA")
                        .expected("As per OpenAPI schema")
                        .actual("Response structure differs")
                        .message("AI detected: " + issuesStr)
                        .severity(Vulnerability.Severity.MEDIUM)
                        .build());
                }
                
                // Отсутствующие поля
                @SuppressWarnings("unchecked")
                List<String> missingFields = (List<String>) result.get("missingFields");
                if (missingFields != null && !missingFields.isEmpty()) {
                    mismatches.add(ContractMismatch.builder()
                        .endpoint(path)
                        .method(method)
                        .type("MISSING_FIELDS")
                        .expected(String.join(", ", missingFields))
                        .actual("Not present in response")
                        .message("AI detected missing fields from schema")
                        .severity(Vulnerability.Severity.LOW)
                        .build());
                }
                
                // Дополнительные поля
                @SuppressWarnings("unchecked")
                List<String> extraFields = (List<String>) result.get("extraFields");
                if (extraFields != null && !extraFields.isEmpty()) {
                    mismatches.add(ContractMismatch.builder()
                        .endpoint(path)
                        .method(method)
                        .type("EXTRA_FIELDS")
                        .expected("Not in schema")
                        .actual(String.join(", ", extraFields))
                        .message("AI detected undocumented fields")
                        .severity(Vulnerability.Severity.LOW)
                        .build());
                }
                
                // Type mismatches
                @SuppressWarnings("unchecked")
                List<Map<String, String>> typeMismatches = (List<Map<String, String>>) result.get("typeMismatches");
                if (typeMismatches != null && !typeMismatches.isEmpty()) {
                    for (Map<String, String> mismatch : typeMismatches) {
                        mismatches.add(ContractMismatch.builder()
                            .endpoint(path)
                            .method(method)
                            .type("TYPE_MISMATCH")
                            .expected(mismatch.get("expected"))
                            .actual(mismatch.get("actual"))
                            .message("AI detected type mismatch in field: " + mismatch.get("field"))
                            .severity(Vulnerability.Severity.MEDIUM)
                            .build());
                    }
                }
            }
            
            log.info("[AI_CONTRACT] Validation Summary for {} {}:", method, path);
            log.info("[AI_CONTRACT]   Valid: {}", isValid);
            log.info("[AI_CONTRACT]   Mismatches found: {}", mismatches.size());
            if (!mismatches.isEmpty()) {
                mismatches.forEach(m -> {
                    log.info("[AI_CONTRACT]     - {}: {}", m.getType(), m.getMessage());
                });
            }
            log.info("=".repeat(80));
            
        } catch (Exception e) {
            log.error("[AI_CONTRACT] Error parsing AI validation result: {}", e.getMessage(), e);
            log.error("[AI_CONTRACT] Raw response was: {}", aiValidationResult);
        }
        
        return mismatches;
    }
    
    private String extractJsonFromResponse(String response) {
        String cleaned = response.trim();
        if (cleaned.startsWith("```json")) {
            cleaned = cleaned.substring(7);
        } else if (cleaned.startsWith("```")) {
            cleaned = cleaned.substring(3);
        }
        if (cleaned.endsWith("```")) {
            cleaned = cleaned.substring(0, cleaned.length() - 3);
        }
        
        // Найти первую { и последнюю }
        int start = cleaned.indexOf("{");
        int end = cleaned.lastIndexOf("}");
        if (start != -1 && end != -1 && end > start) {
            cleaned = cleaned.substring(start, end + 1);
        }
        
        return cleaned.trim();
    }

    private String extractEntityFromPath(String path) {
        // Извлекает имя сущности из пути (допускает дефисы, не убирает их, не учитывает множественное число)
        // Например: "/account/{account_id}" -> "account", "/accounts/{account_id}" -> "accounts", "/account-info/{id}" -> "account-info"
        String[] parts = path.split("/");
        for (String part : parts) {
            if (!part.isEmpty() && !part.startsWith("{")) {
                return part;
            }
        }
        return null;
    }
}


