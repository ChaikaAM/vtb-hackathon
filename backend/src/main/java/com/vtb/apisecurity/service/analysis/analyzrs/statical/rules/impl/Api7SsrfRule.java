package com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.impl;

import com.vtb.apisecurity.model.Vulnerability;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.Rule;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.media.Schema;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

@Slf4j
public class Api7SsrfRule implements Rule {
    
    private static final Pattern URL_PARAM_PATTERN = Pattern.compile(
            "^(?i)(url|uri|link|endpoint|resource|fetch|proxy|redirect)$"
    );

    @Override
    public int getOrder() {
        return 7;
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
    
    private void checkPathItem(String path, PathItem pathItem, List<Vulnerability> vulnerabilities) {
        List<Operation> operations = new ArrayList<>();
        if (pathItem.getGet() != null) operations.add(pathItem.getGet());
        if (pathItem.getPost() != null) operations.add(pathItem.getPost());
        if (pathItem.getPut() != null) operations.add(pathItem.getPut());
        
        for (Operation operation : operations) {
            String method = getMethod(pathItem, operation);
            
            // Check parameters
            if (operation.getParameters() != null) {
                for (Parameter param : operation.getParameters()) {
                    if (URL_PARAM_PATTERN.matcher(param.getName()).matches()) {
                        vulnerabilities.add(Vulnerability.builder()
                                .id(UUID.randomUUID().toString())
                                .owaspCategory("API7:2023")
                                .title("Potential SSRF Vulnerability")
                                .description("Parameter '" + param.getName() + "' in " + path + 
                                        " accepts URL which could lead to SSRF")
                                .severity(Vulnerability.Severity.HIGH)
                                .endpoint(path)
                                .method(method)
                                .parameter(param.getName())
                                .recommendation("Validate and sanitize all user-supplied URLs. Use allowlists of permitted domains/IPs")
                                .build());
                    }
                }
            }
            
            // Check request body
            if (operation.getRequestBody() != null && operation.getRequestBody().getContent() != null) {
                operation.getRequestBody().getContent().forEach((mediaType, mediaTypeObject) -> {
                    if (mediaTypeObject.getSchema() != null) {
                        checkSchemaForUrl(path, mediaTypeObject.getSchema(), vulnerabilities, method);
                    }
                });
            }
        }
    }
    
    private void checkSchemaForUrl(String path, Schema<?> schema, List<Vulnerability> vulnerabilities, String method) {
        if (schema.getProperties() != null) {
            schema.getProperties().forEach((fieldName, fieldSchema) -> {
                if (URL_PARAM_PATTERN.matcher(fieldName).matches()) {
                    String format = fieldSchema instanceof Schema ? ((Schema<?>) fieldSchema).getFormat() : null;
                    if (format == null || format.equals("uri") || format.equals("url")) {
                        vulnerabilities.add(Vulnerability.builder()
                                .id(UUID.randomUUID().toString())
                                .owaspCategory("API7:2023")
                                .title("Potential SSRF Vulnerability")
                                .description("Field '" + fieldName + "' in " + path + 
                                        " accepts URL which could lead to SSRF")
                                .severity(Vulnerability.Severity.HIGH)
                                .endpoint(path)
                                .method(method)
                                .parameter(fieldName)
                                .recommendation("Validate and sanitize all user-supplied URLs. Block access to private IP addresses")
                                .build());
                    }
                }
            });
        }
    }
    
    private String getMethod(PathItem pathItem, Operation operation) {
        if (pathItem.getGet() == operation) return "GET";
        if (pathItem.getPost() == operation) return "POST";
        if (pathItem.getPut() == operation) return "PUT";
        if (pathItem.getDelete() == operation) return "DELETE";
        if (pathItem.getPatch() == operation) return "PATCH";
        return "UNKNOWN";
    }
    
    @Override
    public String getRuleId() {
        return "API7:2023";
    }
    
    @Override
    public String getDescription() {
        return "Server Side Request Forgery";
    }
}

