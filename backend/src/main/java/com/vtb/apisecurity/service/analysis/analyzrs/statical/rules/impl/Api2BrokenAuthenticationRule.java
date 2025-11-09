package com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.impl;

import com.vtb.apisecurity.model.Vulnerability;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.Rule;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import io.swagger.v3.oas.models.security.SecurityScheme;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

@Slf4j
public class Api2BrokenAuthenticationRule implements Rule {
    
    private static final Pattern SENSITIVE_PARAM_PATTERN = Pattern.compile(
            "^(?i)(password|secret|token|key|auth|credential|api[_-]?key)$"
    );

    @Override
    public int getOrder() {
        return 2;
    }

    @Override
    public List<Vulnerability> check(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Check for credentials in query parameters
        checkCredentialsInQueryParams(openAPI, vulnerabilities);
        
        // Check security schemes
        checkSecuritySchemes(openAPI, vulnerabilities);
        
        // Check for endpoints without authentication
        checkUnauthenticatedEndpoints(openAPI, vulnerabilities);
        
        return vulnerabilities;
    }
    
    private void checkCredentialsInQueryParams(OpenAPI openAPI, List<Vulnerability> vulnerabilities) {
        if (openAPI.getPaths() == null) {
            return;
        }
        
        openAPI.getPaths().forEach((path, pathItem) -> {
            List<Operation> operations = getOperations(pathItem);
            
            for (Operation operation : operations) {
                if (operation.getParameters() != null) {
                    for (Parameter param : operation.getParameters()) {
                        if (param.getIn().equals("query")) {
                            String paramName = param.getName().toLowerCase();
                            if (SENSITIVE_PARAM_PATTERN.matcher(paramName).matches()) {
                                String method = getMethod(pathItem, operation);
                                vulnerabilities.add(Vulnerability.builder()
                                        .id(UUID.randomUUID().toString())
                                        .owaspCategory("API2:2023")
                                        .title("Credentials in Query Parameters")
                                        .description("Parameter '" + param.getName() + "' in " + path + 
                                                " contains sensitive authentication data in query string")
                                        .severity(Vulnerability.Severity.HIGH)
                                        .endpoint(path)
                                        .method(method)
                                        .parameter(param.getName())
                                        .recommendation("Never expose credentials in URLs. Use Authorization header instead")
                                        .build());
                            }
                        }
                    }
                }
            }
        });
    }
    
    private void checkSecuritySchemes(OpenAPI openAPI, List<Vulnerability> vulnerabilities) {
        if (openAPI.getComponents() == null || openAPI.getComponents().getSecuritySchemes() == null) {
            vulnerabilities.add(Vulnerability.builder()
                    .id(UUID.randomUUID().toString())
                    .owaspCategory("API2:2023")
                    .title("Missing Security Schemes")
                    .description("OpenAPI specification does not define security schemes")
                    .severity(Vulnerability.Severity.MEDIUM)
                    .recommendation("Define security schemes in components.securitySchemes")
                    .build());
            return;
        }
        
        // Check if security schemes are properly configured
        for (SecurityScheme scheme : openAPI.getComponents().getSecuritySchemes().values()) {
            if (scheme.getType() == SecurityScheme.Type.HTTP) {
                if (scheme.getScheme() == null || !scheme.getScheme().equalsIgnoreCase("bearer")) {
                    vulnerabilities.add(Vulnerability.builder()
                            .id(UUID.randomUUID().toString())
                            .owaspCategory("API2:2023")
                            .title("Weak Security Scheme")
                            .description("Security scheme uses non-Bearer authentication")
                            .severity(Vulnerability.Severity.MEDIUM)
                            .recommendation("Use Bearer token authentication (JWT)")
                            .build());
                }
            }
        }
    }
    
    private void checkUnauthenticatedEndpoints(OpenAPI openAPI, List<Vulnerability> vulnerabilities) {
        if (openAPI.getPaths() == null) {
            return;
        }
        
        boolean hasGlobalSecurity = openAPI.getSecurity() != null && !openAPI.getSecurity().isEmpty();
        
        openAPI.getPaths().forEach((path, pathItem) -> {
            List<Operation> operations = getOperations(pathItem);
            
            for (Operation operation : operations) {
                boolean hasOperationSecurity = operation.getSecurity() != null && !operation.getSecurity().isEmpty();
                
                // Skip health/well-known endpoints
                if (path.contains("/health") || path.contains("/.well-known") || path.equals("/")) {
                    continue;
                }
                
                if (!hasOperationSecurity && !hasGlobalSecurity) {
                    String method = getMethod(pathItem, operation);
                    vulnerabilities.add(Vulnerability.builder()
                            .id(UUID.randomUUID().toString())
                            .owaspCategory("API2:2023")
                            .title("Unauthenticated Endpoint")
                            .description("Endpoint " + path + " does not require authentication")
                            .severity(Vulnerability.Severity.MEDIUM)
                            .endpoint(path)
                            .method(method)
                            .recommendation("Require authentication for sensitive endpoints")
                            .build());
                }
            }
        });
    }
    
    private List<Operation> getOperations(PathItem pathItem) {
        List<Operation> operations = new ArrayList<>();
        if (pathItem.getGet() != null) operations.add(pathItem.getGet());
        if (pathItem.getPost() != null) operations.add(pathItem.getPost());
        if (pathItem.getPut() != null) operations.add(pathItem.getPut());
        if (pathItem.getDelete() != null) operations.add(pathItem.getDelete());
        if (pathItem.getPatch() != null) operations.add(pathItem.getPatch());
        return operations;
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
        return "API2:2023";
    }
    
    @Override
    public String getDescription() {
        return "Broken Authentication";
    }
}

