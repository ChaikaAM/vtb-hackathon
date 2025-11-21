package com.vtb.apisecurity.controller;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.vtb.apisecurity.model.entity.EntityOperation;
import com.vtb.apisecurity.model.entity.EntityRequestsResult;
import com.vtb.apisecurity.model.entity.GeneratedRequest;
import com.vtb.apisecurity.service.analysis.entity.AiRequestGeneratorService;
import com.vtb.apisecurity.service.analysis.entity.EntityOperationExtractor;
import com.vtb.apisecurity.service.openapi.OpenApiParserService;

import io.swagger.v3.oas.models.OpenAPI;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RestController
@RequestMapping("/api/entity-requests")
@Slf4j
@AllArgsConstructor
public class EntityRequestController {
    
    private final OpenApiParserService parserService;
    private final EntityOperationExtractor extractor;
    private final AiRequestGeneratorService generatorService;
    
    /**
     * Генерирует набор запросов для конкретной сущности
     */
    @PostMapping("/generate")
    public EntityRequestsResult generateEntityRequests(
            @RequestParam String openApiUrl,
            @RequestParam String entityName) {
        
        log.info("Generating requests for entity: {} from spec: {}", entityName, openApiUrl);
        
        try {
            // Парсинг OpenAPI
            OpenAPI openAPI = parserService.parseFromUrl(openApiUrl);
            
            // Извлечение операций
            List<EntityOperation> operations = extractor.extractEntityOperations(openAPI, entityName);
            
            if (operations.isEmpty()) {
                log.warn("No operations found for entity: {}", entityName);
            }
            
            // Генерация запросов с помощью ИИ (без токена для standalone режима)
            List<GeneratedRequest> requests = generatorService.generateRequestsForEntity(
                operations, openAPI, entityName, null);
            
            // Группировать по типу операции
            Map<String, List<GeneratedRequest>> groupedByType = groupRequestsByType(requests);
            
            return EntityRequestsResult.builder()
                .entityName(entityName)
                .operationsCount(operations.size())
                .requests(requests)
                .groupedByType(groupedByType)
                .summary(String.format(
                    "Generated %d complete requests for entity '%s' with all headers, parameters and body",
                    requests.size(), entityName
                ))
                .build();
                
        } catch (Exception e) {
            log.error("Error generating entity requests: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to generate entity requests: " + e.getMessage());
        }
    }
    
    /**
     * Генерирует запросы для всех сущностей в API
     */
    @PostMapping("/generate-all")
    public Map<String, Object> generateAllEntityRequests(
            @RequestParam String openApiUrl) {
        
        log.info("Generating requests for all entities from spec: {}", openApiUrl);
        
        try {
            // Парсинг OpenAPI
            OpenAPI openAPI = parserService.parseFromUrl(openApiUrl);
            
            // Найти все сущности
            List<String> entities = discoverEntities(openAPI);
            log.info("Discovered {} entities: {}", entities.size(), entities);
            
            // Для каждой сущности сгенерировать запросы
            Map<String, List<GeneratedRequest>> allRequests = new HashMap<>();
            int totalRequests = 0;
            
            for (String entity : entities) {
                try {
                    List<EntityOperation> ops = extractor.extractEntityOperations(openAPI, entity);
                    if (!ops.isEmpty()) {
                        // Standalone режим - без токена (будет использован placeholder)
                        List<GeneratedRequest> requests = generatorService.generateRequestsForEntity(
                            ops, openAPI, entity, null);
                        allRequests.put(entity, requests);
                        totalRequests += requests.size();
                        log.info("Generated {} requests for entity: {}", requests.size(), entity);
                    }
                } catch (Exception e) {
                    log.error("Error generating requests for entity {}: {}", entity, e.getMessage(), e);
                }
            }
            
            return Map.of(
                "entities", entities,
                "requests", allRequests,
                "totalRequests", totalRequests,
                "summary", String.format(
                    "Generated %d requests across %d entities",
                    totalRequests, entities.size()
                )
            );
            
        } catch (Exception e) {
            log.error("Error generating all entity requests: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to generate entity requests: " + e.getMessage());
        }
    }
    
    /**
     * Обнаруживает все сущности в API (упрощённо — только первое значение после / из path)
     * Сохраняет дефисы в именах сущностей (например, "account-consents" остается "account-consents")
     */
    private List<String> discoverEntities(OpenAPI openAPI) {
        Set<String> entities = new HashSet<>();
        if (openAPI.getPaths() != null) {
            for (String path : openAPI.getPaths().keySet()) {
                String entity = extractEntityFromPath(path);
                if (entity != null && !entity.equals("auth") && !entity.equals("health")) {
                    // Сохраняем имя сущности как есть, с дефисами
                    entities.add(entity);
                }
            }
        }
        return new ArrayList<>(entities);
    }

    private String extractEntityFromPath(String path) {
        // Извлекаем первое значение после "/" — entity (например, "/account-consents/request" -> "account-consents")
        // Важно: сохраняем дефисы в имени сущности
        String[] parts = path.split("/");
        for (String part : parts) {
            if (!part.isEmpty() && !part.startsWith("{") && !part.equals(".well-known")) {
                // Возвращаем часть пути как есть, сохраняя дефисы
                return part;
            }
        }
        return null;
    }
    /* 
     * Группирует запросы по типу операции
     */
    private Map<String, List<GeneratedRequest>> groupRequestsByType(List<GeneratedRequest> requests) {
        Map<String, List<GeneratedRequest>> grouped = new HashMap<>();
        
        for (GeneratedRequest request : requests) {
            String type = determineOperationType(request);
            grouped.computeIfAbsent(type, k -> new ArrayList<>()).add(request);
        }
        
        return grouped;
    }
    
    private String determineOperationType(GeneratedRequest request) {
        String method = request.getMethod().toUpperCase();
        String path = request.getPath().toLowerCase();
        
        if (method.equals("POST") && !path.contains("{")) {
            return "CREATE";
        } else if (method.equals("GET") && path.contains("{")) {
            return "READ_BY_ID";
        } else if (method.equals("GET")) {
            return "READ_LIST";
        } else if (method.equals("PUT") || method.equals("PATCH")) {
            return "UPDATE";
        } else if (method.equals("DELETE")) {
            return "DELETE";
        }
        
        return "OTHER";
    }
}

