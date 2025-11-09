package com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.impl;

import com.vtb.apisecurity.model.Vulnerability;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.Rule;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.parameters.Parameter;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

@Slf4j
public class Api10UnsafeConsumptionRule implements Rule {
    
    private static final List<String> THIRD_PARTY_INDICATORS = Arrays.asList(
        "external", "third-party", "webhook", "callback", "proxy", 
        "fetch", "remote", "integration", "partner"
    );
    
    private static final Pattern URL_PARAM_PATTERN = Pattern.compile(
            "^(?i)(url|uri|link|endpoint|webhook|callback)$"
    );
    
    private static final Pattern EXTERNAL_DATA_PATTERN = Pattern.compile(
            "(?i)(external|third[-_]party|remote|partner|integration)[-_]?(data|response|payload|content)"
    );

    @Override
    public int getOrder() {
        return 10;
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
        String lowerPath = path.toLowerCase();
        
        // Check if path involves third-party integration
        boolean isThirdPartyEndpoint = THIRD_PARTY_INDICATORS.stream()
                .anyMatch(lowerPath::contains);
        
        List<Operation> operations = new ArrayList<>();
        if (pathItem.getGet() != null) operations.add(pathItem.getGet());
        if (pathItem.getPost() != null) operations.add(pathItem.getPost());
        if (pathItem.getPut() != null) operations.add(pathItem.getPut());
        
        for (Operation operation : operations) {
            String method = getMethod(pathItem, operation);
            
            String description = operation.getDescription() != null ? 
                    operation.getDescription().toLowerCase() : "";
            String summary = operation.getSummary() != null ? 
                    operation.getSummary().toLowerCase() : "";
            
            String fullText = description + " " + summary + " " + lowerPath;
            
            // Check for third-party data consumption
            boolean consumesThirdPartyData = EXTERNAL_DATA_PATTERN.matcher(fullText).find();
            
            if (isThirdPartyEndpoint || consumesThirdPartyData) {
                checkThirdPartyDataValidation(path, method, operation, fullText, vulnerabilities);
            }
            
            // Check for webhook/callback endpoints
            if (lowerPath.contains("webhook") || lowerPath.contains("callback")) {
                checkWebhookSecurity(path, method, operation, fullText, vulnerabilities);
            }
            
            // Check for proxy/fetch endpoints
            if (lowerPath.contains("proxy") || lowerPath.contains("fetch")) {
                checkProxyEndpoint(path, method, operation, vulnerabilities);
            }
            
            // Check request body for external data
            if (operation.getRequestBody() != null && operation.getRequestBody().getContent() != null) {
                checkRequestBodyForExternalData(path, method, operation, vulnerabilities);
            }
        }
    }
    
    private void checkThirdPartyDataValidation(String path, String method, Operation operation, 
                                               String fullText, List<Vulnerability> vulnerabilities) {
        // Check if validation is mentioned
        boolean mentionsValidation = fullText.contains("validat") || 
                                    fullText.contains("sanitiz") ||
                                    fullText.contains("filter") ||
                                    fullText.contains("verify");
        
        boolean mentionsHttps = fullText.contains("https") || 
                               fullText.contains("tls") ||
                               fullText.contains("ssl");
        
        if (!mentionsValidation) {
            vulnerabilities.add(Vulnerability.builder()
                    .id(UUID.randomUUID().toString())
                    .owaspCategory("API10:2023")
                    .title("Missing Validation for Third-Party Data")
                    .description("Endpoint " + path + " consumes third-party data without documented validation")
                    .severity(Vulnerability.Severity.HIGH)
                    .endpoint(path)
                    .method(method)
                    .recommendation("Treat all data from third-party APIs as untrusted input and validate thoroughly. " +
                            "Implement input validation and sanitization. Use allowlists for expected data formats")
                    .build());
        }
        
        if (!mentionsHttps) {
            vulnerabilities.add(Vulnerability.builder()
                    .id(UUID.randomUUID().toString())
                    .owaspCategory("API10:2023")
                    .title("Third-Party Communication Security Not Documented")
                    .description("Endpoint " + path + " integrates with third-party services without mentioning HTTPS/TLS")
                    .severity(Vulnerability.Severity.MEDIUM)
                    .endpoint(path)
                    .method(method)
                    .recommendation("Use HTTPS/TLS for all third-party API communications. " +
                            "Verify SSL/TLS certificates to prevent man-in-the-middle attacks")
                    .build());
        }
    }
    
    private void checkWebhookSecurity(String path, String method, Operation operation, 
                                     String fullText, List<Vulnerability> vulnerabilities) {
        // Check for webhook signature verification
        boolean mentionsSignature = fullText.contains("signature") || 
                                   fullText.contains("hmac") ||
                                   fullText.contains("verify") ||
                                   fullText.contains("authentic");
        
        boolean hasSecretParam = false;
        if (operation.getParameters() != null) {
            for (Parameter param : operation.getParameters()) {
                String paramName = param.getName().toLowerCase();
                if (paramName.contains("signature") || paramName.contains("hmac")) {
                    hasSecretParam = true;
                    break;
                }
            }
        }
        
        if (!mentionsSignature && !hasSecretParam) {
            vulnerabilities.add(Vulnerability.builder()
                    .id(UUID.randomUUID().toString())
                    .owaspCategory("API10:2023")
                    .title("Webhook Without Signature Verification")
                    .description("Webhook endpoint " + path + " does not document signature verification mechanism")
                    .severity(Vulnerability.Severity.HIGH)
                    .endpoint(path)
                    .method(method)
                    .recommendation("Implement webhook signature verification using HMAC or similar mechanism. " +
                            "Verify the source of webhook data before processing. " +
                            "Use IP allowlisting for known webhook sources")
                    .build());
        }
    }
    
    private void checkProxyEndpoint(String path, String method, Operation operation, 
                                   List<Vulnerability> vulnerabilities) {
        vulnerabilities.add(Vulnerability.builder()
                .id(UUID.randomUUID().toString())
                .owaspCategory("API10:2023")
                .title("Proxy Endpoint Risks")
                .description("Endpoint " + path + " acts as proxy which may consume untrusted third-party data")
                .severity(Vulnerability.Severity.MEDIUM)
                .endpoint(path)
                .method(method)
                .recommendation("Validate all data from proxied/fetched sources. " +
                        "Implement timeouts and circuit breakers. " +
                        "Use content security policies to prevent injection attacks")
                .build());
    }
    
    private void checkRequestBodyForExternalData(String path, String method, Operation operation, 
                                                 List<Vulnerability> vulnerabilities) {
        operation.getRequestBody().getContent().forEach((mediaType, mediaTypeObject) -> {
            if (mediaTypeObject.getSchema() != null) {
                checkSchemaForExternalData(path, method, mediaTypeObject.getSchema(), vulnerabilities);
            }
        });
    }
    
    private void checkSchemaForExternalData(String path, String method, Schema<?> schema, 
                                           List<Vulnerability> vulnerabilities) {
        if (schema.getProperties() != null) {
            schema.getProperties().forEach((fieldName, fieldSchema) -> {
                if (EXTERNAL_DATA_PATTERN.matcher(fieldName).find()) {
                    vulnerabilities.add(Vulnerability.builder()
                            .id(UUID.randomUUID().toString())
                            .owaspCategory("API10:2023")
                            .title("External Data Field Without Validation")
                            .description("Field '" + fieldName + "' in " + path + 
                                    " appears to contain third-party data")
                            .severity(Vulnerability.Severity.MEDIUM)
                            .endpoint(path)
                            .method(method)
                            .parameter(fieldName)
                            .recommendation("Validate and sanitize all third-party data. " +
                                    "Use allowlists for expected formats. " +
                                    "Implement proper error handling")
                            .build());
                }
                
                // Check nested schemas recursively
                if (fieldSchema instanceof Schema) {
                    checkSchemaForExternalData(path, method, (Schema<?>) fieldSchema, vulnerabilities);
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
        return "API10:2023";
    }
    
    @Override
    public String getDescription() {
        return "Unsafe Consumption of APIs";
    }
}

