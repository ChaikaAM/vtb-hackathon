package com.vtb.apisecurity.service.analysis.entity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vtb.apisecurity.model.entity.EntityOperation;
import com.vtb.apisecurity.model.entity.MediaTypeInfo;
import com.vtb.apisecurity.model.entity.OperationRequest;
import com.vtb.apisecurity.model.entity.ParameterInfo;
import com.vtb.apisecurity.model.entity.RequestBodyInfo;
import com.vtb.apisecurity.model.entity.SchemaInfo;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class EntityOperationExtractor {
    
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    /**
     * Извлекает все операции для сущности из OpenAPI
     */
    public List<EntityOperation> extractEntityOperations(OpenAPI openAPI, String entityName) {
        log.info("Extracting operations for entity: {}", entityName);
        
        List<EntityOperation> operations = new ArrayList<>();
        
        if (openAPI.getPaths() == null) {
            return operations;
        }
        
        // Найти все пути связанные с сущностью
        Map<String, PathItem> entityPaths = findEntityPaths(openAPI, entityName);
        log.info("Found {} paths for entity: {}", entityPaths.size(), entityName);
        
        // Извлечь операции из каждого пути
        for (Map.Entry<String, PathItem> entry : entityPaths.entrySet()) {
            String path = entry.getKey();
            PathItem pathItem = entry.getValue();
            
            // GET
            if (pathItem.getGet() != null) {
                operations.add(extractOperation("GET", path, pathItem.getGet(), openAPI));
            }
            
            // POST
            if (pathItem.getPost() != null) {
                operations.add(extractOperation("POST", path, pathItem.getPost(), openAPI));
            }
            
            // PUT
            if (pathItem.getPut() != null) {
                operations.add(extractOperation("PUT", path, pathItem.getPut(), openAPI));
            }
            
            // PATCH
            if (pathItem.getPatch() != null) {
                operations.add(extractOperation("PATCH", path, pathItem.getPatch(), openAPI));
            }
            
            // DELETE
            if (pathItem.getDelete() != null) {
                operations.add(extractOperation("DELETE", path, pathItem.getDelete(), openAPI));
            }
        }
        
        log.info("Extracted {} operations for entity: {}", operations.size(), entityName);
        return operations;
    }
    
    /**
     * Находит все пути связанные с сущностью
     */
    private Map<String, PathItem> findEntityPaths(OpenAPI openAPI, String entityName) {
        Map<String, PathItem> entityPaths = new HashMap<>();
        String entityLower = entityName.toLowerCase();

        openAPI.getPaths().forEach((path, pathItem) -> {
            String pathLower = path.toLowerCase();

            // Совпадение без каких-либо преобразований дефисов
            boolean matches =
                    pathLower.contains("/" + entityLower + "/") ||
                    pathLower.contains("/" + entityLower + "-") ||
                    pathLower.contains("/" + entityLower + "{") ||
                    pathLower.equals("/" + entityLower);

            if (matches) {
                entityPaths.put(path, pathItem);
            }

            // Проверка по тегам операции
            if (hasEntityInOperations(pathItem, entityName)) {
                entityPaths.put(path, pathItem);
            }
        });

        return entityPaths;
    }
    
    private boolean hasEntityInOperations(PathItem pathItem, String entityName) {
        return (pathItem.getGet() != null && hasEntityTag(pathItem.getGet(), entityName)) ||
               (pathItem.getPost() != null && hasEntityTag(pathItem.getPost(), entityName)) ||
               (pathItem.getPut() != null && hasEntityTag(pathItem.getPut(), entityName)) ||
               (pathItem.getPatch() != null && hasEntityTag(pathItem.getPatch(), entityName)) ||
               (pathItem.getDelete() != null && hasEntityTag(pathItem.getDelete(), entityName));
    }
    
    private boolean hasEntityTag(Operation operation, String entityName) {
        if (operation.getTags() == null) {
            return false;
        }
        return operation.getTags().stream()
            .anyMatch(tag -> tag.toLowerCase().contains(entityName.toLowerCase()));
    }
    
    /**
     * Извлекает полную информацию об операции
     */
    private EntityOperation extractOperation(String method, String path, Operation operation, OpenAPI openAPI) {
        EntityOperation entityOp = EntityOperation.builder()
            .method(method)
            .path(path)
            .operationId(operation.getOperationId())
            .summary(operation.getSummary())
            .description(operation.getDescription())
            .tags(operation.getTags())
            .build();
        
        // Извлечь параметры
        OperationRequest request = extractRequest(operation, openAPI);
        entityOp.setRequest(request);
        
        // Извлечь security requirements
        List<Map<String, List<String>>> security = null;
        if (operation.getSecurity() != null) {
            security = operation.getSecurity().stream()
                .map(req -> (Map<String, List<String>>) req)
                .collect(Collectors.toList());
        } else if (openAPI.getSecurity() != null) {
            security = openAPI.getSecurity().stream()
                .map(req -> (Map<String, List<String>>) req)
                .collect(Collectors.toList());
        }
        entityOp.setSecurityRequirements(security);
        
        return entityOp;
    }
    
    /**
     * Извлекает полную информацию о запросе
     */
    private OperationRequest extractRequest(Operation operation, OpenAPI openAPI) {
        OperationRequest request = OperationRequest.builder().build();
        
        Map<String, ParameterInfo> pathParams = new HashMap<>();
        Map<String, ParameterInfo> queryParams = new HashMap<>();
        Map<String, ParameterInfo> headerParams = new HashMap<>();
        
        if (operation.getParameters() != null) {
            for (Parameter param : operation.getParameters()) {
                ParameterInfo paramInfo = extractParameterInfo(param, openAPI);
                
                switch (param.getIn()) {
                    case "path":
                        pathParams.put(param.getName(), paramInfo);
                        break;
                    case "query":
                        queryParams.put(param.getName(), paramInfo);
                        break;
                    case "header":
                        headerParams.put(param.getName(), paramInfo);
                        break;
                }
            }
        }
        
        request.setPathParameters(pathParams.isEmpty() ? null : pathParams);
        request.setQueryParameters(queryParams.isEmpty() ? null : queryParams);
        request.setHeaderParameters(headerParams.isEmpty() ? null : headerParams);
        
        // RequestBody
        if (operation.getRequestBody() != null) {
            RequestBodyInfo bodyInfo = extractRequestBodyInfo(operation.getRequestBody(), openAPI);
            request.setRequestBody(bodyInfo);
        }
        
        return request;
    }
    
    /**
     * Извлекает информацию о параметре
     */
    private ParameterInfo extractParameterInfo(Parameter param, OpenAPI openAPI) {
        ParameterInfo info = ParameterInfo.builder()
            .name(param.getName())
            .in(param.getIn())
            .required(param.getRequired() != null && param.getRequired())
            .description(param.getDescription())
            .build();
        
        // Schema параметра
        if (param.getSchema() != null) {
            Schema<?> schema = param.getSchema();
            info.setType(schema.getType());
            info.setFormat(schema.getFormat());
            info.setExample(schema.getExample());
            info.setDefaultValue(schema.getDefault());
            if (schema.getEnum() != null) {
                info.setEnumValues(new ArrayList<>(schema.getEnum()));
            }
        }
        
        // Извлечь пример из параметра (приоритет над schema.example)
        if (param.getExample() != null) {
            info.setExample(param.getExample());
        }
        
        // Извлечь примеры
        if (param.getExamples() != null && !param.getExamples().isEmpty()) {
            Map<String, Object> examples = param.getExamples().entrySet().stream()
                .collect(Collectors.toMap(
                    Map.Entry::getKey,
                    e -> e.getValue().getValue()
                ));
            info.setExamples(examples);
        }
        
        return info;
    }
    
    /**
     * Извлекает информацию о RequestBody
     */
    private RequestBodyInfo extractRequestBodyInfo(io.swagger.v3.oas.models.parameters.RequestBody requestBody, OpenAPI openAPI) {
        RequestBodyInfo bodyInfo = RequestBodyInfo.builder()
            .required(requestBody.getRequired() != null && requestBody.getRequired())
            .description(requestBody.getDescription())
            .build();
        
        if (requestBody.getContent() != null) {
            Map<String, MediaTypeInfo> contentMap = new HashMap<>();
            
            requestBody.getContent().forEach((mediaType, mediaTypeObject) -> {
                MediaTypeInfo mediaInfo = MediaTypeInfo.builder()
                    .mediaType(mediaType)
                    .build();
                
                // Schema
                if (mediaTypeObject.getSchema() != null) {
                    SchemaInfo schemaInfo = extractSchemaInfo(mediaTypeObject.getSchema(), openAPI);
                    mediaInfo.setSchema(schemaInfo);
                }
                
                // Example
                if (mediaTypeObject.getExample() != null) {
                    mediaInfo.setExample(mediaTypeObject.getExample());
                }
                
                // Examples
                if (mediaTypeObject.getExamples() != null && !mediaTypeObject.getExamples().isEmpty()) {
                    Map<String, Object> examples = mediaTypeObject.getExamples().entrySet().stream()
                        .collect(Collectors.toMap(
                            Map.Entry::getKey,
                            e -> e.getValue().getValue()
                        ));
                    mediaInfo.setExamples(examples);
                }
                
                contentMap.put(mediaType, mediaInfo);
            });
            
            bodyInfo.setContent(contentMap);
        }
        
        return bodyInfo;
    }
    
    /**
     * Рекурсивно извлекает информацию о схеме
     */
    private SchemaInfo extractSchemaInfo(Schema<?> schema, OpenAPI openAPI) {
        // Resolve $ref если есть
        if (schema.get$ref() != null) {
            Schema<?> resolvedSchema = resolveSchemaRef(schema.get$ref(), openAPI);
            if (resolvedSchema != null) {
                schema = resolvedSchema;
            }
        }
        
        SchemaInfo schemaInfo = SchemaInfo.builder()
            .type(schema.getType())
            .format(schema.getFormat())
            .description(schema.getDescription())
            .example(schema.getExample())
            .defaultValue(schema.getDefault())
            .enumValues(schema.getEnum() != null ? new ArrayList<>(schema.getEnum()) : null)
            .pattern(schema.getPattern())
            .build();
        
        // Constraints
        if (schema.getMinimum() != null) {
            schemaInfo.setMinimum(schema.getMinimum().intValue());
        }
        if (schema.getMaximum() != null) {
            schemaInfo.setMaximum(schema.getMaximum().intValue());
        }
        
        // Properties для object
        if (schema.getProperties() != null && !schema.getProperties().isEmpty()) {
            Map<String, SchemaInfo> properties = new HashMap<>();
            schema.getProperties().forEach((name, propSchema) -> {
                properties.put(name, extractSchemaInfo(propSchema, openAPI));
            });
            schemaInfo.setProperties(properties);
        }
        
        // Required fields
        if (schema.getRequired() != null && !schema.getRequired().isEmpty()) {
            schemaInfo.setRequiredFields(schema.getRequired());
        }
        
        // Items для array
        if (schema.getItems() != null) {
            schemaInfo.setItems(extractSchemaInfo(schema.getItems(), openAPI));
        }
        
        return schemaInfo;
    }
    
    private Schema<?> resolveSchemaRef(String ref, OpenAPI openAPI) {
        if (ref.startsWith("#/components/schemas/")) {
            String schemaName = ref.substring("#/components/schemas/".length());
            if (openAPI.getComponents() != null && 
                openAPI.getComponents().getSchemas() != null) {
                return openAPI.getComponents().getSchemas().get(schemaName);
            }
        }
        return null;
    }
}

