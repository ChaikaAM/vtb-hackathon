package com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.impl;

import com.vtb.apisecurity.model.Vulnerability;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.Rule;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

@Slf4j
public class Api1BrokenObjectLevelAuthRule implements Rule {
    
    private static final Pattern PATH_PARAM_PATTERN = Pattern.compile("\\{[^}]+\\}");
    private static final Pattern SEQUENTIAL_ID_PATTERN = Pattern.compile("\\d+");

    @Override
    public int getOrder() {
        return 1;
    }

    @Override
    public List<Vulnerability> check(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        openAPI.getPaths().forEach((path, pathItem) -> {
            // Check for path parameters (e.g., /users/{id})
            if (PATH_PARAM_PATTERN.matcher(path).find()) {
                checkPathItem(path, pathItem, vulnerabilities, openAPI);
            }
        });
        
        return vulnerabilities;
    }
    
    private void checkPathItem(String path, PathItem pathItem, List<Vulnerability> vulnerabilities, OpenAPI openAPI) {
        List<Operation> operations = new ArrayList<>();
        if (pathItem.getGet() != null) operations.add(pathItem.getGet());
        if (pathItem.getPost() != null) operations.add(pathItem.getPost());
        if (pathItem.getPut() != null) operations.add(pathItem.getPut());
        if (pathItem.getDelete() != null) operations.add(pathItem.getDelete());
        if (pathItem.getPatch() != null) operations.add(pathItem.getPatch());
        
        for (Operation operation : operations) {
            String method = getMethod(pathItem, operation);
            
            // Check if security is defined
            boolean hasSecurity = operation.getSecurity() != null && !operation.getSecurity().isEmpty();
            boolean hasGlobalSecurity = openAPI.getSecurity() != null && !openAPI.getSecurity().isEmpty();
            
            if (!hasSecurity && !hasGlobalSecurity) {
                vulnerabilities.add(Vulnerability.builder()
                        .id(UUID.randomUUID().toString())
                        .owaspCategory("API1:2023")
                        .title("Broken Object Level Authorization")
                        .description("Endpoint " + path + " handles object identifiers but lacks authorization checks")
                        .severity(Vulnerability.Severity.HIGH)
                        .endpoint(path)
                        .method(method)
                        .recommendation("Implement proper authorization checks that verify the user has permission to access the requested object")
                        .build());
            }
            
            // Check for sequential IDs in examples
            checkSequentialIds(path, operation, vulnerabilities, method);
        }
    }
    
    private void checkSequentialIds(String path, Operation operation, List<Vulnerability> vulnerabilities, String method) {
        if (operation.getParameters() != null) {
            for (Parameter param : operation.getParameters()) {
                if (param.getIn().equals("path") && param.getExample() != null) {
                    String example = param.getExample().toString();
                    if (SEQUENTIAL_ID_PATTERN.matcher(example).matches()) {
                        vulnerabilities.add(Vulnerability.builder()
                                .id(UUID.randomUUID().toString())
                                .owaspCategory("API1:2023")
                                .title("Predictable Object IDs")
                                .description("Endpoint " + path + " uses sequential IDs which are predictable")
                                .severity(Vulnerability.Severity.MEDIUM)
                                .endpoint(path)
                                .method(method)
                                .parameter(param.getName())
                                .recommendation("Use random, non-sequential IDs (UUIDs) instead of sequential integers")
                                .build());
                    }
                }
            }
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
        return "API1:2023";
    }
    
    @Override
    public String getDescription() {
        return "Broken Object Level Authorization";
    }
}

