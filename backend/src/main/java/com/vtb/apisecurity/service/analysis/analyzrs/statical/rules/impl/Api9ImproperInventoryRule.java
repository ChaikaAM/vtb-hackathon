package com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.impl;

import com.vtb.apisecurity.model.Vulnerability;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.Rule;
import io.swagger.v3.oas.models.OpenAPI;
import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Slf4j
public class Api9ImproperInventoryRule implements Rule {

    @Override
    public int getOrder() {
        return 9;
    }

    @Override
    public List<Vulnerability> check(OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Check for API documentation completeness
        if (openAPI.getInfo() == null || openAPI.getInfo().getDescription() == null || 
            openAPI.getInfo().getDescription().trim().isEmpty()) {
            vulnerabilities.add(Vulnerability.builder()
                    .id(UUID.randomUUID().toString())
                    .owaspCategory("API9:2023")
                    .title("Missing API Description")
                    .description("OpenAPI specification lacks description")
                    .severity(Vulnerability.Severity.LOW)
                    .recommendation("Provide comprehensive API description in info.description")
                    .build());
        }
        
        // Check for deprecated endpoints
        if (openAPI.getPaths() != null) {
            openAPI.getPaths().forEach((path, pathItem) -> {
                if (pathItem.getGet() != null && pathItem.getGet().getDeprecated() != null && pathItem.getGet().getDeprecated()) {
                    vulnerabilities.add(Vulnerability.builder()
                            .id(UUID.randomUUID().toString())
                            .owaspCategory("API9:2023")
                            .title("Deprecated Endpoint Still Available")
                            .description("Endpoint " + path + " is marked as deprecated but still accessible")
                            .severity(Vulnerability.Severity.MEDIUM)
                            .endpoint(path)
                            .method("GET")
                            .recommendation("Remove deprecated endpoints or implement proper deprecation strategy with removal timeline")
                            .build());
                }
            });
        }
        
        return vulnerabilities;
    }
    
    @Override
    public String getRuleId() {
        return "API9:2023";
    }
    
    @Override
    public String getDescription() {
        return "Improper Inventory Management";
    }
}

