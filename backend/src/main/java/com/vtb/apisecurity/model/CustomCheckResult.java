package com.vtb.apisecurity.model;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CustomCheckResult {
    private String checkId;          // ID проверки
    private String checkName;         // Название проверки
    private String category;          // Категория проверки
    private CheckStatus status;       // PASSED, FAILED, WARNING, ERROR
    private String result;            // Текстовый результат от AI
    private String endpoint;          // На какой endpoint проверка (если применимо)
    private String method;            // HTTP метод
    @Builder.Default
    private List<Vulnerability> vulnerabilities = new ArrayList<>(); // Найденные уязвимости (если есть)
    private Map<String, Object> details; // Дополнительные детали
    private LocalDateTime executedAt;
    
    public enum CheckStatus {
        PASSED, FAILED, WARNING, ERROR
    }
}

