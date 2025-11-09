package com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.impl;

import com.vtb.apisecurity.model.Vulnerability;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.Rule;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Slf4j
public class Api5BrokenFunctionLevelAuthRule implements Rule {

    @Override
    public int getOrder() {
        return 5;
    }

    @Override
    public List<Vulnerability> check(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        openAPI.getPaths().forEach((path, pathItem) -> {
            checkPathItem(path, pathItem, vulnerabilities, openAPI);
        });
        
        return vulnerabilities;
    }
    
    private void checkPathItem(String path, PathItem pathItem, List<Vulnerability> vulnerabilities, OpenAPI openAPI) {
        // Check for admin endpoints
        boolean isAdminPath = path.toLowerCase().contains("/admin") || 
                             path.toLowerCase().contains("/management") ||
                             path.toLowerCase().contains("/internal");
        
        List<Operation> operations = new ArrayList<>();
        if (pathItem.getGet() != null) operations.add(pathItem.getGet());
        if (pathItem.getPost() != null) operations.add(pathItem.getPost());
        if (pathItem.getPut() != null) operations.add(pathItem.getPut());
        if (pathItem.getDelete() != null) operations.add(pathItem.getDelete());
        
        for (Operation operation : operations) {
            String method = getMethod(pathItem, operation);
            
            boolean hasSecurity = operation.getSecurity() != null && !operation.getSecurity().isEmpty();
            boolean hasGlobalSecurity = openAPI.getSecurity() != null && !openAPI.getSecurity().isEmpty();
            
            if (isAdminPath && !hasSecurity && !hasGlobalSecurity) {
                vulnerabilities.add(Vulnerability.builder()
                        .id(UUID.randomUUID().toString())
                        .owaspCategory("API5:2023")
                        .title("Unprotected Admin Endpoint")
                        .description("Admin endpoint " + path + " does not require authentication")
                        .severity(Vulnerability.Severity.CRITICAL)
                        .endpoint(path)
                        .method(method)
                        .recommendation("Implement proper authorization checks on all administrative functions. Use RBAC or ABAC")
                        .build());
            }
            
            // Check for sensitive operations without proper security
            if ((method.equals("DELETE") || method.equals("PUT")) && !hasSecurity && !hasGlobalSecurity) {
                vulnerabilities.add(Vulnerability.builder()
                        .id(UUID.randomUUID().toString())
                        .owaspCategory("API5:2023")
                        .title("Missing Authorization on Sensitive Operation")
                        .description("Endpoint " + path + " performs " + method + " operation without explicit security requirements")
                        .severity(Vulnerability.Severity.HIGH)
                        .endpoint(path)
                        .method(method)
                        .recommendation("Implement authorization checks on all sensitive functions and endpoints")
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
        return "API5:2023";
    }
    
    @Override
    public String getDescription() {
        return "Broken Function Level Authorization";
    }
}

