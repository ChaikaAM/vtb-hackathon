package com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.impl;

import com.vtb.apisecurity.model.Vulnerability;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.Rule;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.responses.ApiResponse;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

@Slf4j
public class Api3BrokenPropertyLevelAuthRule implements Rule {
    
    private static final Pattern SENSITIVE_FIELD_PATTERN = Pattern.compile(
            "^(?i)(password|secret|token|key|credit[_-]?card|ssn|social[_-]?security|pin|cv[vc]|security[_-]?code)$"
    );

    @Override
    public int getOrder() {
        return 3;
    }

    @Override
    public List<Vulnerability> check(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        openAPI.getPaths().forEach((path, pathItem) -> {
            checkPathItem(path, pathItem, vulnerabilities);
        });
        
        return vulnerabilities;
    }
    
    private void checkPathItem(String path, io.swagger.v3.oas.models.PathItem pathItem, List<Vulnerability> vulnerabilities) {
        List<io.swagger.v3.oas.models.Operation> operations = new ArrayList<>();
        if (pathItem.getGet() != null) operations.add(pathItem.getGet());
        if (pathItem.getPost() != null) operations.add(pathItem.getPost());
        if (pathItem.getPut() != null) operations.add(pathItem.getPut());
        
        for (io.swagger.v3.oas.models.Operation operation : operations) {
            if (operation.getResponses() != null) {
                for (Map.Entry<String, ApiResponse> responseEntry : operation.getResponses().entrySet()) {
                    ApiResponse response = responseEntry.getValue();
                    if (response.getContent() != null) {
                        response.getContent().forEach((mediaType, mediaTypeObject) -> {
                            if (mediaTypeObject.getSchema() != null) {
                                checkSchema(path, mediaTypeObject.getSchema(), vulnerabilities, "response");
                            }
                        });
                    }
                }
            }
            
            // Check request body
            if (operation.getRequestBody() != null && operation.getRequestBody().getContent() != null) {
                operation.getRequestBody().getContent().forEach((mediaType, mediaTypeObject) -> {
                    if (mediaTypeObject.getSchema() != null) {
                        checkSchema(path, mediaTypeObject.getSchema(), vulnerabilities, "request");
                    }
                });
            }
        }
    }
    
    private void checkSchema(String path, Schema<?> schema, List<Vulnerability> vulnerabilities, String context) {
        if (schema.getProperties() != null) {
            schema.getProperties().forEach((fieldName, fieldSchema) -> {
                if (SENSITIVE_FIELD_PATTERN.matcher(fieldName).matches()) {
                    vulnerabilities.add(Vulnerability.builder()
                            .id(UUID.randomUUID().toString())
                            .owaspCategory("API3:2023")
                            .title("Sensitive Data Exposure")
                            .description("Field '" + fieldName + "' in " + path + " (" + context + 
                                    ") contains sensitive information")
                            .severity(Vulnerability.Severity.HIGH)
                            .endpoint(path)
                            .parameter(fieldName)
                            .recommendation("Filter sensitive properties from responses based on user authorization. Use DTOs to control exposed properties")
                            .build());
                }
            });
        }
        
        // Check nested schemas
        if (schema.getProperties() != null) {
            schema.getProperties().values().forEach(nestedSchema -> {
                if (nestedSchema instanceof Schema) {
                    checkSchema(path, (Schema<?>) nestedSchema, vulnerabilities, context);
                }
            });
        }
    }
    
    @Override
    public String getRuleId() {
        return "API3:2023";
    }
    
    @Override
    public String getDescription() {
        return "Broken Object Property Level Authorization";
    }
}

