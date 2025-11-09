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
public class Api8SecurityMisconfigurationRule implements Rule {

    @Override
    public int getOrder() {
        return 8;
    }

    @Override
    public List<Vulnerability> check(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Check for debug endpoints
        checkDebugEndpoints(openAPI, vulnerabilities);
        
        // Check for versioning
        checkVersioning(openAPI, vulnerabilities);
        
        return vulnerabilities;
    }
    
    private void checkDebugEndpoints(OpenAPI openAPI, List<Vulnerability> vulnerabilities) {
        if (openAPI.getPaths() == null) {
            return;
        }
        
        openAPI.getPaths().forEach((path, pathItem) -> {
            String lowerPath = path.toLowerCase();
            if (lowerPath.contains("/debug") || 
                lowerPath.contains("/test") ||
                lowerPath.contains("/dev") ||
                lowerPath.contains("/admin") ||
                lowerPath.contains("/actuator")) {
                
                List<Operation> operations = new ArrayList<>();
                if (pathItem.getGet() != null) operations.add(pathItem.getGet());
                if (pathItem.getPost() != null) operations.add(pathItem.getPost());
                
                for (Operation operation : operations) {
                    String method = getMethod(pathItem, operation);
                    vulnerabilities.add(Vulnerability.builder()
                            .id(UUID.randomUUID().toString())
                            .owaspCategory("API8:2023")
                            .title("Debug/Test Endpoint Exposed")
                            .description("Endpoint " + path + " appears to be a debug/test endpoint")
                            .severity(Vulnerability.Severity.MEDIUM)
                            .endpoint(path)
                            .method(method)
                            .recommendation("Remove or properly secure debug endpoints in production. Use environment-based configuration")
                            .build());
                }
            }
        });
    }
    
    private void checkVersioning(OpenAPI openAPI, List<Vulnerability> vulnerabilities) {
        String version = openAPI.getInfo() != null ? openAPI.getInfo().getVersion() : null;
        
        if (openAPI.getPaths() != null) {
            boolean hasVersionedPaths = openAPI.getPaths().keySet().stream()
                    .anyMatch(path -> path.contains("/v1/") || path.contains("/v2/") || path.contains("/v3/"));
            
            if (!hasVersionedPaths && version != null) {
                vulnerabilities.add(Vulnerability.builder()
                        .id(UUID.randomUUID().toString())
                        .owaspCategory("API8:2023")
                        .title("Missing API Versioning Strategy")
                        .description("API specification defines version " + version + 
                                " but paths do not include versioning")
                        .severity(Vulnerability.Severity.LOW)
                        .recommendation("Implement proper API versioning strategy in URL paths (e.g., /api/v1/, /api/v2/)")
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
        return "API8:2023";
    }
    
    @Override
    public String getDescription() {
        return "Security Misconfiguration";
    }
}

