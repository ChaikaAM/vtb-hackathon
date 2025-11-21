package com.vtb.apisecurity.model;

import java.util.ArrayList;
import java.util.List;

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
        private List<CustomCheck> customChecks = new ArrayList<>();
    }
    
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CustomCheck {
        private String id;              // Уникальный ID проверки
        private String name;            // Название проверки (для UI)
        private String prompt;          // Промпт для AI
        private String description;     // Описание проверки (опционально)
        private String category;        // Категория (например, "Бизнес-логика", "Безопасность")
        private boolean enabled;        // Включена ли проверка
    }
}

