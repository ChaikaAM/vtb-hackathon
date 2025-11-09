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

@Slf4j
public class Api4UnrestrictedResourceConsumptionRule implements Rule {

    @Override
    public int getOrder() {
        return 4;
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
        
        for (Operation operation : operations) {
            String method = getMethod(pathItem, operation);
            
            // Check for pagination parameters
            boolean hasPagination = false;
            if (operation.getParameters() != null) {
                for (Parameter param : operation.getParameters()) {
                    String paramName = param.getName().toLowerCase();
                    if (paramName.contains("limit") || paramName.contains("page") || paramName.contains("size")) {
                        hasPagination = true;
                        break;
                    }
                }
            }
            
            // Check description for rate limiting mentions
            String description = operation.getDescription() != null ? operation.getDescription().toLowerCase() : "";
            boolean mentionsRateLimit = description.contains("rate limit") || 
                                       description.contains("throttle") ||
                                       description.contains("quota");
            
            if (!hasPagination && (method.equals("GET") || path.contains("list") || path.contains("search"))) {
                vulnerabilities.add(Vulnerability.builder()
                        .id(UUID.randomUUID().toString())
                        .owaspCategory("API4:2023")
                        .title("Missing Pagination")
                        .description("Endpoint " + path + " returns lists without pagination")
                        .severity(Vulnerability.Severity.MEDIUM)
                        .endpoint(path)
                        .method(method)
                        .recommendation("Implement pagination for list endpoints to limit response sizes")
                        .build());
            }
            
            if (!mentionsRateLimit && (method.equals("POST") || method.equals("PUT") || method.equals("DELETE"))) {
                vulnerabilities.add(Vulnerability.builder()
                        .id(UUID.randomUUID().toString())
                        .owaspCategory("API4:2023")
                        .title("No Rate Limiting Mentioned")
                        .description("Endpoint " + path + " does not mention rate limiting in documentation")
                        .severity(Vulnerability.Severity.LOW)
                        .endpoint(path)
                        .method(method)
                        .recommendation("Implement rate limiting on all API endpoints (per user, IP, or API key)")
                        .build());
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
        return "API4:2023";
    }
    
    @Override
    public String getDescription() {
        return "Unrestricted Resource Consumption";
    }
}

