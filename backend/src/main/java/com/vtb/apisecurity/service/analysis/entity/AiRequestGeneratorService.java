package com.vtb.apisecurity.service.analysis.entity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vtb.apisecurity.model.entity.EntityOperation;
import com.vtb.apisecurity.model.entity.GeneratedRequest;
import com.vtb.apisecurity.model.entity.ParameterInfo;
import com.vtb.apisecurity.model.entity.RequestBodyInfo;
import com.vtb.apisecurity.model.entity.SchemaInfo;
import com.vtb.apisecurity.service.ai.AiAgentService;

import io.swagger.v3.oas.models.OpenAPI;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class AiRequestGeneratorService {
    
    private final AiAgentService aiAgentService;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ExecutorService executorService;
    
    @Value("${banking.auth.client-id}")
    private String clientId;
    
    @Value("${ai.parallel.threads:5}")
    private int parallelThreads;
    
    @Value("${ai.parallel.enabled:true}")
    private boolean parallelEnabled;
    
    public AiRequestGeneratorService(AiAgentService aiAgentService) {
        this.aiAgentService = aiAgentService;
        // Пул потоков для параллельной обработки AI запросов
        this.executorService = Executors.newFixedThreadPool(5);
    }
    
    /**
     * Генерирует полный набор запросов для всех операций сущности
     * Поддерживает параллельную обработку для ускорения
     */
    public List<GeneratedRequest> generateRequestsForEntity(
            List<EntityOperation> operations, 
            OpenAPI openAPI, 
            String entityName,
            String authToken) {
        
        log.info("Generating requests for {} operations of entity: {}", operations.size(), entityName);
        if (authToken != null && !authToken.isEmpty()) {
            log.info("Using real auth token in AI prompts (length: {} chars)", authToken.length());
        } else {
            log.warn("No auth token available, will use placeholder");
        }
        log.info("Using client_id in AI prompts: {}", clientId != null ? clientId : "<placeholder>");
        
        if (parallelEnabled && operations.size() > 1) {
            log.info("Parallel AI processing ENABLED with {} threads for {} operations", 
                parallelThreads, operations.size());
            return generateRequestsParallel(operations, openAPI, entityName, authToken);
        } else {
            log.info("Sequential AI processing (parallel disabled or single operation)");
            return generateRequestsSequential(operations, openAPI, entityName, authToken);
        }
    }
    
    /**
     * Последовательная генерация (старый подход)
     */
    private List<GeneratedRequest> generateRequestsSequential(
            List<EntityOperation> operations, 
            OpenAPI openAPI, 
            String entityName,
            String authToken) {
        
        List<GeneratedRequest> generatedRequests = new ArrayList<>();
        
        for (EntityOperation operation : operations) {
            try {
                GeneratedRequest request = generateRequest(operation, openAPI, entityName, authToken);
                generatedRequests.add(request);
                log.info("Generated request for {} {}", operation.getMethod(), operation.getPath());
            } catch (Exception e) {
                log.error("Error generating request for {} {}: {}", 
                    operation.getMethod(), operation.getPath(), e.getMessage(), e);
            }
        }
        
        return generatedRequests;
    }
    
    /**
     * Параллельная генерация запросов (новый подход)
     * Использует CompletableFuture для одновременной обработки нескольких операций
     */
    private List<GeneratedRequest> generateRequestsParallel(
            List<EntityOperation> operations, 
            OpenAPI openAPI, 
            String entityName,
            String authToken) {
        
        long startTime = System.currentTimeMillis();
        
        // Создаем CompletableFuture для каждой операции
        List<CompletableFuture<GeneratedRequest>> futures = operations.stream()
            .map(operation -> CompletableFuture.supplyAsync(() -> {
                try {
                    log.debug("Starting parallel generation for {} {}", 
                        operation.getMethod(), operation.getPath());
                    GeneratedRequest request = generateRequest(operation, openAPI, entityName, authToken);
                    log.info("✓ Generated request for {} {} (parallel)", 
                        operation.getMethod(), operation.getPath());
                    return request;
                } catch (Exception e) {
                    log.error("Error generating request for {} {}: {}", 
                        operation.getMethod(), operation.getPath(), e.getMessage(), e);
                    return null;
                }
            }, executorService))
            .collect(Collectors.toList());
        
        // Ждем завершения всех задач
        CompletableFuture<Void> allOf = CompletableFuture.allOf(
            futures.toArray(new CompletableFuture[0])
        );
        
        try {
            allOf.join(); // Блокируемся до завершения всех
        } catch (Exception e) {
            log.error("Error waiting for parallel tasks: {}", e.getMessage(), e);
        }
        
        // Собираем результаты (исключая null)
        List<GeneratedRequest> generatedRequests = futures.stream()
            .map(CompletableFuture::join)
            .filter(request -> request != null)
            .collect(Collectors.toList());
        
        long duration = System.currentTimeMillis() - startTime;
        log.info("Parallel generation completed: {} requests in {} ms ({} ms avg per request)", 
            generatedRequests.size(), duration, 
            generatedRequests.size() > 0 ? duration / generatedRequests.size() : 0);
        
        return generatedRequests;
    }
    
    /**
     * Генерирует полный запрос для операции с помощью ИИ
     */
    private GeneratedRequest generateRequest(EntityOperation operation, OpenAPI openAPI, String entityName, String authToken) {
        log.info("=".repeat(80));
        log.info("[AI_REQUEST_GENERATOR] Generating request for {} {}", operation.getMethod(), operation.getPath());
        
        // Подготовить контекст для ИИ
        String context = buildContext(operation, openAPI, entityName);
        
        // Промпт для ИИ (с реальным токеном)
        String prompt = buildPrompt(operation, context, authToken);
        
        log.info("[AI_REQUEST_GENERATOR] AI Prompt (length: {} chars):", prompt.length());
        log.info("─".repeat(80));
        log.info("{}", prompt);
        log.info("─".repeat(80));
        
        // Запросить у ИИ
        log.info("[AI_REQUEST_GENERATOR] Calling AI agent...");
        String aiResponse = aiAgentService.generateRequestFromSpec(prompt);
        
        log.info("[AI_REQUEST_GENERATOR] AI Response (length: {} chars):", aiResponse.length());
        log.info("─".repeat(80));
        log.info("{}", aiResponse);
        log.info("─".repeat(80));
        
        // Парсить ответ ИИ
        GeneratedRequest request = parseAiResponse(aiResponse, operation);
        
        log.info("[AI_REQUEST_GENERATOR] Generated request:");
        log.info("  Method: {}", request.getMethod());
        log.info("  Path: {}", request.getPath());
        log.info("  Path Params: {}", request.getPathParameters());
        log.info("  Query Params: {}", request.getQueryParameters());
        log.info("  Headers: {}", maskSensitiveHeaders(request.getHeaders()));
        log.info("  Body: {}", request.getBody() != null ? 
            (request.getBody().toString().length() > 200 ? 
                request.getBody().toString().substring(0, 200) + "..." : 
                request.getBody()) : "null");
        log.info("=".repeat(80));
        
        return request;
    }
    
    /**
     * Маскирует чувствительные данные в headers для логирования
     */
    private Map<String, String> maskSensitiveHeaders(Map<String, String> headers) {
        if (headers == null) {
            return null;
        }
        Map<String, String> masked = new HashMap<>();
        headers.forEach((key, value) -> {
            if ("Authorization".equalsIgnoreCase(key) && value != null && value.startsWith("Bearer ")) {
                masked.put(key, "Bearer ***");
            } else {
                masked.put(key, value);
            }
        });
        return masked;
    }
    
    /**
     * Строит контекст из всех данных операции
     */
    private String buildContext(EntityOperation operation, OpenAPI openAPI, String entityName) {
        StringBuilder context = new StringBuilder();
        
        context.append("=== OpenAPI Operation Context ===\n\n");
        context.append("Entity: ").append(entityName).append("\n");
        context.append("Method: ").append(operation.getMethod()).append("\n");
        context.append("Path: ").append(operation.getPath()).append("\n");
        context.append("Operation ID: ").append(operation.getOperationId()).append("\n\n");
        
        // Описание
        if (operation.getDescription() != null && !operation.getDescription().isEmpty()) {
            context.append("Description:\n").append(operation.getDescription()).append("\n\n");
        }
        
        if (operation.getSummary() != null) {
            context.append("Summary: ").append(operation.getSummary()).append("\n\n");
        }
        
        // Теги
        if (operation.getTags() != null && !operation.getTags().isEmpty()) {
            context.append("Tags: ").append(String.join(", ", operation.getTags())).append("\n\n");
        }
        
        // Path параметры
        if (operation.getRequest().getPathParameters() != null && 
            !operation.getRequest().getPathParameters().isEmpty()) {
            context.append("=== Path Parameters ===\n");
            operation.getRequest().getPathParameters().forEach((name, param) -> {
                context.append(formatParameter(name, param));
            });
            context.append("\n");
        }
        
        // Query параметры
        if (operation.getRequest().getQueryParameters() != null && 
            !operation.getRequest().getQueryParameters().isEmpty()) {
            context.append("=== Query Parameters ===\n");
            operation.getRequest().getQueryParameters().forEach((name, param) -> {
                context.append(formatParameter(name, param));
            });
            context.append("\n");
        }
        
        // Header параметры
        if (operation.getRequest().getHeaderParameters() != null && 
            !operation.getRequest().getHeaderParameters().isEmpty()) {
            context.append("=== Header Parameters ===\n");
            operation.getRequest().getHeaderParameters().forEach((name, param) -> {
                context.append(formatParameter(name, param));
            });
            context.append("\n");
        }
        
        // RequestBody
        if (operation.getRequest().getRequestBody() != null) {
            context.append("=== Request Body ===\n");
            RequestBodyInfo body = operation.getRequest().getRequestBody();
            
            if (body.getDescription() != null) {
                context.append("Description: ").append(body.getDescription()).append("\n");
            }
            context.append("Required: ").append(body.isRequired()).append("\n\n");
            
            if (body.getContent() != null) {
                body.getContent().forEach((mediaType, mediaInfo) -> {
                    context.append("Media Type: ").append(mediaType).append("\n");
                    
                    if (mediaInfo.getSchema() != null) {
                        context.append("Schema:\n");
                        context.append(formatSchema(mediaInfo.getSchema(), 1));
                    }
                    
                    if (mediaInfo.getExample() != null) {
                        context.append("Example:\n").append(formatExample(mediaInfo.getExample())).append("\n");
                    }
                    
                    if (mediaInfo.getExamples() != null && !mediaInfo.getExamples().isEmpty()) {
                        context.append("Examples:\n");
                        mediaInfo.getExamples().forEach((exampleName, example) -> {
                            context.append("  ").append(exampleName).append(":\n");
                            context.append(formatExample(example)).append("\n");
                        });
                    }
                });
            }
            context.append("\n");
        }
        
        // Security requirements
        if (operation.getSecurityRequirements() != null && !operation.getSecurityRequirements().isEmpty()) {
            context.append("=== Security Requirements ===\n");
            operation.getSecurityRequirements().forEach(security -> {
                security.forEach((schemeName, scopes) -> {
                    context.append("- ").append(schemeName);
                    if (scopes != null && !scopes.isEmpty()) {
                        context.append(" (scopes: ").append(String.join(", ", scopes)).append(")");
                    }
                    context.append("\n");
                });
            });
            context.append("\n");
        }
        
        // Security schemes из OpenAPI
        if (openAPI.getComponents() != null && openAPI.getComponents().getSecuritySchemes() != null) {
            context.append("=== Available Security Schemes ===\n");
            openAPI.getComponents().getSecuritySchemes().forEach((name, scheme) -> {
                context.append("- ").append(name).append(": ").append(scheme.getType());
                if (scheme.getScheme() != null) {
                    context.append(" (").append(scheme.getScheme()).append(")");
                }
                if (scheme.getDescription() != null) {
                    context.append(" - ").append(scheme.getDescription());
                }
                context.append("\n");
            });
            context.append("\n");
        }
        
        return context.toString();
    }
    
    private String formatParameter(String name, ParameterInfo param) {
        StringBuilder sb = new StringBuilder();
        sb.append("- ").append(name).append(": ").append(param.getType() != null ? param.getType() : "unknown");
        sb.append(" (").append(param.isRequired() ? "required" : "optional").append(")");
        
        if (param.getDescription() != null && !param.getDescription().isEmpty()) {
            sb.append("\n  Description: ").append(param.getDescription());
        }
        
        if (param.getExample() != null) {
            sb.append("\n  Example: ").append(param.getExample());
        }
        
        if (param.getDefaultValue() != null) {
            sb.append("\n  Default: ").append(param.getDefaultValue());
        }
        
        if (param.getEnumValues() != null && !param.getEnumValues().isEmpty()) {
            sb.append("\n  Enum: ").append(param.getEnumValues());
        }
        
        sb.append("\n");
        return sb.toString();
    }
    
    /**
     * Форматирует схему для промпта
     */
    private String formatSchema(SchemaInfo schema, int indent) {
        StringBuilder sb = new StringBuilder();
        String indentStr = "  ".repeat(indent);
        
        sb.append(indentStr).append("Type: ").append(schema.getType() != null ? schema.getType() : "unknown");
        if (schema.getFormat() != null) {
            sb.append(" (").append(schema.getFormat()).append(")");
        }
        sb.append("\n");
        
        if (schema.getDescription() != null && !schema.getDescription().isEmpty()) {
            sb.append(indentStr).append("Description: ").append(schema.getDescription()).append("\n");
        }
        
        if (schema.getRequiredFields() != null && !schema.getRequiredFields().isEmpty()) {
            sb.append(indentStr).append("Required: ").append(String.join(", ", schema.getRequiredFields())).append("\n");
        }
        
        if (schema.getProperties() != null && !schema.getProperties().isEmpty()) {
            sb.append(indentStr).append("Properties:\n");
            schema.getProperties().forEach((propName, propSchema) -> {
                sb.append(indentStr).append("  - ").append(propName);
                boolean isRequired = schema.getRequiredFields() != null && 
                                   schema.getRequiredFields().contains(propName);
                if (isRequired) {
                    sb.append(" (required)");
                }
                sb.append(":\n");
                sb.append(formatSchema(propSchema, indent + 2));
            });
        }
        
        if (schema.getItems() != null) {
            sb.append(indentStr).append("Items:\n");
            sb.append(formatSchema(schema.getItems(), indent + 1));
        }
        
        if (schema.getExample() != null) {
            sb.append(indentStr).append("Example: ").append(schema.getExample()).append("\n");
        }
        
        if (schema.getEnumValues() != null && !schema.getEnumValues().isEmpty()) {
            sb.append(indentStr).append("Enum: ").append(schema.getEnumValues()).append("\n");
        }
        
        return sb.toString();
    }
    
    private String formatExample(Object example) {
        if (example == null) {
            return "null";
        }
        if (example instanceof String) {
            return (String) example;
        }
        try {
            return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(example);
        } catch (Exception e) {
            return example.toString();
        }
    }
    
    /**
     * Строит промпт для ИИ с реальным токеном и client_id
     */
    private String buildPrompt(EntityOperation operation, String context, String authToken) {
        // Определяем какой токен использовать в примере и инструкциях
        String authHeaderExample;
        String authInstruction;
        
        if (authToken != null && !authToken.isEmpty()) {
            authHeaderExample = String.format("\"Authorization\": \"Bearer %s\"", authToken);
            authInstruction = String.format(
                "- ДЛЯ Authorization используй ТОЧНО это значение: Bearer %s\n" +
                "- НЕ изменяй токен, используй его как есть", 
                authToken
            );
            log.debug("[AI_REQUEST_GENERATOR] Using real auth token in prompt (length: {} chars)", authToken.length());
        } else {
            authHeaderExample = "\"Authorization\": \"Bearer <token>\"";
            authInstruction = "- ДЛЯ Authorization используй placeholder: Bearer <token>";
            log.debug("[AI_REQUEST_GENERATOR] Using placeholder token in prompt");
        }
        
        // Определяем какой client_id использовать
        String clientIdValue = (clientId != null && !clientId.isEmpty()) ? clientId : "team200-1";
        String clientIdInstruction = String.format(
            "- ДЛЯ client_id используй ТОЧНО это значение: %s",
            clientIdValue
        );
        log.debug("[AI_REQUEST_GENERATOR] Using client_id in prompt: {}", clientIdValue);
        
        return String.format(
            "На основе OpenAPI спецификации сгенерируй полный HTTP запрос для операции.\n\n" +
            "%s\n\n" +
            "Задача:\n" +
            "1. Сгенерируй все обязательные Headers:\n" +
            "   - Authorization header из security requirements\n" +
            "   - Все header параметры из спецификации\n" +
            "   - Используй примеры из описания операции\n\n" +
            "2. Сгенерируй Query параметры:\n" +
            "   - Все обязательные query параметры\n" +
            "   - Опциональные с разумными значениями\n" +
            "   - Используй примеры из спецификации\n\n" +
            "3. Сгенерируй Path параметры:\n" +
            "   - Используй примеры из спецификации\n" +
            "   - Если примеров нет, сгенерируй валидное значение на основе типа\n\n" +
            "4. Сгенерируй Request Body (если есть):\n" +
            "   - Используй схему для генерации валидного JSON\n" +
            "   - Используй примеры из спецификации\n" +
            "   - Заполни все обязательные поля\n" +
            "   - Добавь опциональные поля с разумными значениями\n\n" +
            "5. Учти все детали из описания операции\n\n" +
            "6. Для операций CREATE определи JSONPath для извлечения ID из ответа\n" +
            "   (например: 'data.accountId', 'id', 'data.id')\n\n" +
            "Верни ТОЛЬКО валидный JSON без объяснений в формате:\n" +
            "{\n" +
            "  \"method\": \"%s\",\n" +
            "  \"path\": \"%s\",\n" +
            "  \"pathParameters\": {\"account_id\": \"acc-1010\"},\n" +
            "  \"queryParameters\": {\"client_id\": \"%s\", \"page\": 1},\n" +
            "  \"headers\": {\n" +
            "    %s,\n" +
            "    \"X-Consent-Id\": \"consent-example\",\n" +
            "    \"X-Requesting-Bank\": \"team200\"\n" +
            "  },\n" +
            "  \"body\": {\"account_type\": \"checking\", \"initial_balance\": 0},\n" +
            "  \"extractIdFrom\": \"data.id\",\n" +
            "  \"description\": \"Краткое описание что делает этот запрос\"\n" +
            "}\n\n" +
            "ВАЖНО:\n" +
            "- Используй ВСЕ поля из описания операции\n" +
            "- Включи ВСЕ headers упомянутые в описании и параметрах\n" +
            "- Используй примеры из спецификации где возможно\n" +
            "- Генерируй реалистичные тестовые данные\n" +
            "- body должен быть null для GET/DELETE без body\n" +
            "- pathParameters должен быть {} для путей без параметров\n" +
            "%s\n" +
            "%s",
            context,
            operation.getMethod(),
            operation.getPath(),
            clientIdValue,
            authHeaderExample,
            authInstruction,
            clientIdInstruction
        );
    }
    
    /**
     * Парсит ответ ИИ
     */
    private GeneratedRequest parseAiResponse(String aiResponse, EntityOperation operation) {
        try {
            // Извлечь JSON из ответа (может быть обернут в markdown)
            String cleanJson = extractJsonFromResponse(aiResponse);
            
            @SuppressWarnings("unchecked")
            Map<String, Object> responseMap = objectMapper.readValue(cleanJson, Map.class);
            
            GeneratedRequest request = GeneratedRequest.builder()
                .method((String) responseMap.get("method"))
                .path((String) responseMap.get("path"))
                .description((String) responseMap.get("description"))
                .extractIdFrom((String) responseMap.get("extractIdFrom"))
                .build();
            
            // Path параметры
            if (responseMap.containsKey("pathParameters")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> pathParams = (Map<String, Object>) responseMap.get("pathParameters");
                request.setPathParameters(pathParams);
            }
            
            // Query параметры
            if (responseMap.containsKey("queryParameters")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> queryParams = (Map<String, Object>) responseMap.get("queryParameters");
                request.setQueryParameters(queryParams);
            }
            
            // Headers
            if (responseMap.containsKey("headers")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> headersObj = (Map<String, Object>) responseMap.get("headers");
                Map<String, String> headers = new HashMap<>();
                headersObj.forEach((k, v) -> headers.put(k, v != null ? v.toString() : null));
                request.setHeaders(headers);
            }
            
            // Body
            if (responseMap.containsKey("body")) {
                request.setBody(responseMap.get("body"));
            }
            
            return request;
            
        } catch (Exception e) {
            log.error("Error parsing AI response: {}. Response: {}", e.getMessage(), aiResponse, e);
            // Fallback: создать базовый запрос
            return createFallbackRequest(operation);
        }
    }
    
    private String extractJsonFromResponse(String response) {
        // Убрать markdown code blocks если есть
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
    
    private GeneratedRequest createFallbackRequest(EntityOperation operation) {
        log.warn("Creating fallback request for {} {}", operation.getMethod(), operation.getPath());
        
        GeneratedRequest request = GeneratedRequest.builder()
            .method(operation.getMethod())
            .path(operation.getPath())
            .description(operation.getSummary())
            .build();
        
        // Базовые headers из security
        Map<String, String> headers = new HashMap<>();
        if (operation.getSecurityRequirements() != null && !operation.getSecurityRequirements().isEmpty()) {
            headers.put("Authorization", "Bearer <token>");
        }
        request.setHeaders(headers);
        
        // Path параметры из примеров
        if (operation.getRequest().getPathParameters() != null) {
            Map<String, Object> pathParams = new HashMap<>();
            operation.getRequest().getPathParameters().forEach((name, param) -> {
                if (param.getExample() != null) {
                    pathParams.put(name, param.getExample());
                }
            });
            if (!pathParams.isEmpty()) {
                request.setPathParameters(pathParams);
            }
        }
        
        return request;
    }
}

