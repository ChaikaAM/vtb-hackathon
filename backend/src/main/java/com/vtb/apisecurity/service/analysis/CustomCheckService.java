package com.vtb.apisecurity.service.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vtb.apisecurity.model.CustomCheckResult;
import com.vtb.apisecurity.model.ScanRequest;
import com.vtb.apisecurity.model.Vulnerability;
import com.vtb.apisecurity.service.ai.AiAgentService;
import io.swagger.v3.core.util.Json;
import io.swagger.v3.oas.models.OpenAPI;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
@Slf4j
@RequiredArgsConstructor
public class CustomCheckService {
    
    private final AiAgentService aiAgentService;
    private final ObjectMapper objectMapper;
    
    /**
     * Выполняет пользовательскую проверку через AI
     */
    public CustomCheckResult executeCheck(
            ScanRequest.CustomCheck check, 
            OpenAPI openAPI, 
            String apiBaseUrl, 
            String authToken) {
        
        log.info("[CUSTOM_CHECK] Executing check: {} (ID: {})", check.getName(), check.getId());
        
        try {
            // Формируем промпт с контекстом OpenAPI спецификации
            String fullPrompt = buildPrompt(check, openAPI, apiBaseUrl);
            
            // Вызываем AI для выполнения проверки
            String aiResponse = aiAgentService.generateRequestFromSpec(fullPrompt);
            
            // Парсим результат и создаем CustomCheckResult
            return parseCheckResult(check, aiResponse, openAPI);
            
        } catch (Exception e) {
            log.error("[CUSTOM_CHECK] Error executing check {}: {}", check.getName(), e.getMessage(), e);
            return CustomCheckResult.builder()
                    .checkId(check.getId())
                    .checkName(check.getName())
                    .category(check.getCategory())
                    .status(CustomCheckResult.CheckStatus.ERROR)
                    .result("Ошибка выполнения проверки: " + e.getMessage())
                    .executedAt(LocalDateTime.now())
                    .build();
        }
    }
    
    private String buildPrompt(ScanRequest.CustomCheck check, OpenAPI openAPI, String apiBaseUrl) {
        // Сериализуем OpenAPI в JSON для промпта
        String openApiJson;
        try {
            openApiJson = Json.pretty(openAPI);
            // Ограничиваем размер, чтобы не превысить лимиты токенов
            if (openApiJson.length() > 10000) {
                openApiJson = openApiJson.substring(0, 10000) + "\n... (спецификация обрезана для экономии токенов)";
            }
        } catch (Exception e) {
            log.warn("[CUSTOM_CHECK] Failed to serialize OpenAPI spec: {}", e.getMessage());
            openApiJson = "Не удалось сериализовать OpenAPI спецификацию";
        }
        
        // Добавляем контекст OpenAPI спецификации к пользовательскому промпту
        return String.format(
            "Ты выполняешь проверку безопасности и качества API.\n\n" +
            "=== Контекст ===\n" +
            "API Base URL: %s\n" +
            "OpenAPI спецификация (JSON):\n%s\n\n" +
            "=== Задача проверки ===\n" +
            "%s\n\n" +
            "=== Инструкции ===\n" +
            "Проанализируй API согласно задаче выше и верни результат в формате JSON:\n" +
            "{\n" +
            "  \"status\": \"PASSED|FAILED|WARNING|ERROR\",\n" +
            "  \"result\": \"Детальное описание результата проверки на русском языке\",\n" +
            "  \"vulnerabilities\": [{\"title\": \"Название проблемы\", \"description\": \"Описание\", \"severity\": \"HIGH|MEDIUM|LOW\", \"owaspCategory\": \"API1:2023\", \"endpoint\": \"/path\", \"method\": \"GET\"}],\n" +
            "  \"affectedEndpoints\": [\"/endpoint1\", \"/endpoint2\"],\n" +
            "  \"details\": {\"key\": \"value\"}\n" +
            "}\n\n" +
            "ВАЖНО:\n" +
            "- Ответь ТОЛЬКО валидным JSON объектом, без дополнительных символов, без markdown разметки, без тройных кавычек\n" +
            "- Начни ответ сразу с открывающей фигурной скобки { и закончи закрывающей фигурной скобкой }\n" +
            "- Если проверка прошла успешно, используй status: \"PASSED\"\n" +
            "- Если найдены проблемы, используй status: \"FAILED\" или \"WARNING\"\n" +
            "- Если произошла ошибка при проверке, используй status: \"ERROR\"\n" +
            "- В поле vulnerabilities укажи найденные проблемы как уязвимости\n" +
            "- В поле result дай подробное описание результата проверки на русском языке",
            apiBaseUrl,
            openApiJson,
            check.getPrompt()
        );
    }
    
    private CustomCheckResult parseCheckResult(
            ScanRequest.CustomCheck check, 
            String aiResponse, 
            OpenAPI openAPI) {
        
        try {
            // Очищаем ответ от возможных markdown разметки
            String cleanedResponse = cleanMarkdownCodeBlocks(aiResponse);
            
            log.debug("[CUSTOM_CHECK] Parsing AI response for check {}: {}", check.getName(), 
                cleanedResponse.length() > 500 ? cleanedResponse.substring(0, 500) + "..." : cleanedResponse);
            
            // Парсим JSON ответ от AI
            @SuppressWarnings("unchecked")
            Map<String, Object> resultMap = (Map<String, Object>) objectMapper.readValue(cleanedResponse, Map.class);
            
            CustomCheckResult.CheckStatus status = CustomCheckResult.CheckStatus.ERROR;
            if (resultMap.containsKey("status")) {
                String statusStr = ((String) resultMap.get("status")).toUpperCase();
                try {
                    status = CustomCheckResult.CheckStatus.valueOf(statusStr);
                } catch (IllegalArgumentException e) {
                    log.warn("[CUSTOM_CHECK] Unknown status: {}, using ERROR", statusStr);
                }
            }
            
            String result = resultMap.containsKey("result") ? 
                (String) resultMap.get("result") : "Результат проверки не получен";
            
            List<Vulnerability> vulnerabilities = new ArrayList<>();
            if (resultMap.containsKey("vulnerabilities")) {
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> vulnsList = (List<Map<String, Object>>) resultMap.get("vulnerabilities");
                for (Map<String, Object> vulnMap : vulnsList) {
                    Vulnerability vuln = new Vulnerability();
                    vuln.setTitle((String) vulnMap.getOrDefault("title", "Проблема безопасности"));
                    vuln.setDescription((String) vulnMap.getOrDefault("description", ""));
                    vuln.setOwaspCategory((String) vulnMap.getOrDefault("owaspCategory", "CUSTOM"));
                    vuln.setEndpoint((String) vulnMap.getOrDefault("endpoint", null));
                    vuln.setMethod((String) vulnMap.getOrDefault("method", null));
                    
                    String severityStr = (String) vulnMap.getOrDefault("severity", "MEDIUM");
                    try {
                        vuln.setSeverity(Vulnerability.Severity.valueOf(severityStr.toUpperCase()));
                    } catch (IllegalArgumentException e) {
                        vuln.setSeverity(Vulnerability.Severity.MEDIUM);
                    }
                    
                    vuln.setDetectedAt(LocalDateTime.now());
                    vulnerabilities.add(vuln);
                }
            }
            
            @SuppressWarnings("unchecked")
            Map<String, Object> details = resultMap.containsKey("details") ? 
                (Map<String, Object>) resultMap.get("details") : new HashMap<>();
            
            CustomCheckResult checkResult = CustomCheckResult.builder()
                    .checkId(check.getId())
                    .checkName(check.getName())
                    .category(check.getCategory())
                    .status(status)
                    .result(result)
                    .vulnerabilities(vulnerabilities)
                    .details(details)
                    .executedAt(LocalDateTime.now())
                    .build();
            
            log.info("[CUSTOM_CHECK] Check {} completed with status: {}, found {} vulnerabilities", 
                check.getName(), status, vulnerabilities.size());
            
            return checkResult;
            
        } catch (Exception e) {
            log.error("[CUSTOM_CHECK] Failed to parse AI response for check {}: {}", 
                check.getName(), e.getMessage(), e);
            log.debug("[CUSTOM_CHECK] Raw AI response: {}", aiResponse);
            
            // Если не удалось распарсить, возвращаем результат с текстом ответа
            return CustomCheckResult.builder()
                    .checkId(check.getId())
                    .checkName(check.getName())
                    .category(check.getCategory())
                    .status(CustomCheckResult.CheckStatus.WARNING)
                    .result("Не удалось распарсить результат AI. Ответ: " + 
                        (aiResponse.length() > 500 ? aiResponse.substring(0, 500) + "..." : aiResponse))
                    .executedAt(LocalDateTime.now())
                    .build();
        }
    }
    
    /**
     * Очищает ответ от markdown разметки (тройные обратные кавычки)
     */
    private String cleanMarkdownCodeBlocks(String text) {
        if (text == null) {
            return null;
        }
        text = text.trim();
        
        // Удаляем ``` в начале (может быть с указанием языка типа ```json)
        if (text.startsWith("```")) {
            text = text.substring(3);
            // Удаляем возможное указание языка (json, например) до переноса строки
            int newlineIndex = text.indexOf('\n');
            if (newlineIndex >= 0) {
                text = text.substring(newlineIndex + 1);
            } else {
                // Если нет переноса строки, просто удаляем пробелы
                text = text.trim();
            }
        }
        
        // Удаляем ``` в конце
        text = text.trim();
        if (text.endsWith("```")) {
            text = text.substring(0, text.length() - 3);
        }
        
        // Удаляем возможные пустые строки в начале и конце
        return text.trim();
    }
}

