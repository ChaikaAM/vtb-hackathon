package com.vtb.apisecurity.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScanHistory {
    private String scanId;
    private String openApiUrl;
    private String apiBaseUrl;
    private String bankName;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private Long durationMs;
    private ScanResult.ScanStatus status;
    private ScanRequest.ScanOptions options;
    private String description; // Описание параметров анализа
    
    public String getDescription() {
        if (description != null) {
            return description;
        }
        
        StringBuilder desc = new StringBuilder();
        if (bankName != null && !bankName.isEmpty()) {
            desc.append(bankName).append(" - ");
        }
        
        if (options != null) {
            boolean hasAny = false;
            if (options.isEnableStaticAnalysis()) {
                desc.append("Статический анализ");
                hasAny = true;
            }
            if (options.isEnableDynamicTesting()) {
                if (hasAny) desc.append(", ");
                desc.append("Динамическое тестирование");
                hasAny = true;
            }
            if (options.isEnableContractValidation()) {
                if (hasAny) desc.append(", ");
                desc.append("Валидация контракта");
                hasAny = true;
            }
            if (options.isEnableAiAnalysis()) {
                if (hasAny) desc.append(", ");
                desc.append("AI анализ");
                hasAny = true;
            }
            if (!hasAny) {
                desc.append("Базовый анализ");
            }
        } else {
            desc.append("Базовый анализ");
        }
        
        return desc.toString();
    }
    
    public Long getCurrentDurationMs() {
        if (durationMs != null) {
            return durationMs;
        }
        if (startTime != null && status == ScanResult.ScanStatus.RUNNING) {
            return java.time.Duration.between(startTime, LocalDateTime.now()).toMillis();
        }
        return 0L;
    }
}

