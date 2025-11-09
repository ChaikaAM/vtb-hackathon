package com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.impl;

import com.vtb.apisecurity.model.Vulnerability;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.Rule;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.parameters.Parameter;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

@Slf4j
public class Api6UnrestrictedBusinessFlowRule implements Rule {
    
    // Business-sensitive operations keywords
    private static final List<String> BUSINESS_FLOW_KEYWORDS = Arrays.asList(
        "payment", "transfer", "purchase", "order", "buy", "sell", "trade",
        "create", "register", "signup", "book", "reserve", "apply",
        "withdraw", "deposit", "loan", "credit", "product-agreement"
    );
    
    private static final Pattern CAPTCHA_PATTERN = Pattern.compile(
            "(?i)(captcha|recaptcha|hcaptcha|challenge|verification)"
    );

    @Override
    public int getOrder() {
        return 6;
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
        
        // Check if path represents a sensitive business flow
        boolean isSensitiveBusinessFlow = BUSINESS_FLOW_KEYWORDS.stream()
                .anyMatch(lowerPath::contains);
        
        if (!isSensitiveBusinessFlow) {
            return;
        }
        
        List<Operation> operations = new ArrayList<>();
        if (pathItem.getPost() != null) operations.add(pathItem.getPost());
        if (pathItem.getPut() != null) operations.add(pathItem.getPut());
        if (pathItem.getDelete() != null) operations.add(pathItem.getDelete());
        
        for (Operation operation : operations) {
            String method = getMethod(pathItem, operation);
            
            String description = operation.getDescription() != null ? 
                    operation.getDescription().toLowerCase() : "";
            String summary = operation.getSummary() != null ? 
                    operation.getSummary().toLowerCase() : "";
            
            String fullText = description + " " + summary;
            
            // Check for rate limiting mentions
            boolean mentionsRateLimit = fullText.contains("rate limit") || 
                                       fullText.contains("throttle") ||
                                       fullText.contains("quota") ||
                                       fullText.contains("limit");
            
            // Check for CAPTCHA or bot protection
            boolean hasCaptchaProtection = CAPTCHA_PATTERN.matcher(fullText).find();
            
            // Check for business logic protection mentions
            boolean mentionsBusinessLogic = fullText.contains("one per user") ||
                                          fullText.contains("maximum") ||
                                          fullText.contains("limit per") ||
                                          fullText.contains("once per");
            
            // Check if endpoint has parameters indicating automation protection
            boolean hasProtectionParams = false;
            if (operation.getParameters() != null) {
                for (Parameter param : operation.getParameters()) {
                    String paramName = param.getName().toLowerCase();
                    if (CAPTCHA_PATTERN.matcher(paramName).find()) {
                        hasProtectionParams = true;
                        break;
                    }
                }
            }
            
            // If no protection mechanisms mentioned for sensitive business flow
            if (!mentionsRateLimit && !hasCaptchaProtection && 
                !mentionsBusinessLogic && !hasProtectionParams) {
                
                Vulnerability.Severity severity = determineSeverity(path);
                
                vulnerabilities.add(Vulnerability.builder()
                        .id(UUID.randomUUID().toString())
                        .owaspCategory("API6:2023")
                        .title("Unrestricted Access to Sensitive Business Flow")
                        .description("Endpoint " + path + " performs sensitive business operation (" + 
                                extractBusinessType(path) + ") without documented protection against automation")
                        .severity(severity)
                        .endpoint(path)
                        .method(method)
                        .recommendation("Implement rate limiting and quotas on sensitive business flows. " +
                                "Use CAPTCHA or similar mechanisms to prevent automation. " +
                                "Implement business logic rules to detect and prevent abuse " +
                                "(e.g., one transaction per user per time period, limited operations per day)")
                        .build());
            }
            
            // Check for mass operations without safeguards
            if (lowerPath.contains("batch") || lowerPath.contains("bulk") || 
                fullText.contains("multiple") || fullText.contains("mass")) {
                
                if (!mentionsRateLimit && !mentionsBusinessLogic) {
                    vulnerabilities.add(Vulnerability.builder()
                            .id(UUID.randomUUID().toString())
                            .owaspCategory("API6:2023")
                            .title("Bulk Operation Without Safeguards")
                            .description("Endpoint " + path + " allows bulk/batch operations without documented limits")
                            .severity(Vulnerability.Severity.HIGH)
                            .endpoint(path)
                            .method(method)
                            .recommendation("Implement strict limits on bulk operations. " +
                                    "Monitor for unusual patterns. Implement progressive delays for repeated operations")
                            .build());
                }
            }
        }
    }
    
    private String extractBusinessType(String path) {
        String lowerPath = path.toLowerCase();
        for (String keyword : BUSINESS_FLOW_KEYWORDS) {
            if (lowerPath.contains(keyword)) {
                return keyword;
            }
        }
        return "business operation";
    }
    
    private Vulnerability.Severity determineSeverity(String path) {
        String lowerPath = path.toLowerCase();
        
        // Critical business flows
        if (lowerPath.contains("payment") || lowerPath.contains("transfer") || 
            lowerPath.contains("withdraw") || lowerPath.contains("loan")) {
            return Vulnerability.Severity.HIGH;
        }
        
        // Medium severity business flows
        if (lowerPath.contains("purchase") || lowerPath.contains("order") || 
            lowerPath.contains("book") || lowerPath.contains("product-agreement")) {
            return Vulnerability.Severity.MEDIUM;
        }
        
        return Vulnerability.Severity.MEDIUM;
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
        return "API6:2023";
    }
    
    @Override
    public String getDescription() {
        return "Unrestricted Access to Sensitive Business Flows";
    }
}

