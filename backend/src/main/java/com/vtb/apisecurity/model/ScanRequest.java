package com.vtb.apisecurity.model;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ScanRequest {
    @NotBlank(message = "OpenAPI URL is required")
    private String openApiUrl;
    
    @NotBlank(message = "API Base URL is required")
    private String apiBaseUrl;

    private ScanOptions options;
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class ScanOptions {
        private boolean enableStaticAnalysis = false;
        private boolean enableDynamicTesting = false;
        private boolean enableContractValidation = false;
        private boolean enableAiAnalysis = true;
        private int timeoutMs = 300000; // 5 minutes
        private int maxConcurrentRequests = 10;
    }
}

