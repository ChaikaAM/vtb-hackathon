package com.vtb.apisecurity.service.ai;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.vtb.apisecurity.model.GptResponse;
import com.vtb.apisecurity.model.Vulnerability;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

@Service
@Slf4j
@RequiredArgsConstructor
public class AiAgentService {

    private final ObjectMapper objectMapper;
    private final OkHttpClient aiAgentClient;
    
    @Value("${yandexgpt.api-url}")
    private String apiUrl;
    
    @Value("${yandexgpt.enabled:true}")
    private boolean enabled;
    
    @Value("${yandexgpt.api-key}")
    private String apiKey;
    
    @Value("${yandexgpt.folder-id}")
    private String folderId;
    
    @Value("${yandexgpt.modelUri}")
    private String modelUri;

    public List<Vulnerability> analyzeVulnerabilities(List<Vulnerability> vulnerabilities) {
        if (!isConfigurationValid() || vulnerabilities.isEmpty()) {
            if (!isConfigurationValid() && enabled) {
                log.warn("Yandex GPT is not properly configured. Skipping AI analysis.");
            }
            return vulnerabilities;
        }

        log.info("Sending {} vulnerabilities to AI agent for analysis", vulnerabilities.size());
        List<Vulnerability> analyzedVulnerabilities = new ArrayList<>();

        for (Vulnerability vuln : vulnerabilities) {
            try {
                Vulnerability analyzed = analyzeVulnerability(vuln);
                analyzedVulnerabilities.add(analyzed);
            } catch (Exception e) {
                log.error("Error analyzing vulnerability with AI: {}", e.getMessage(), e);
                // Return original vulnerability if AI analysis fails
                analyzedVulnerabilities.add(vuln);
            }
        }

        return analyzedVulnerabilities;
    }

    public List<Vulnerability> filterFalsePositives(List<Vulnerability> vulnerabilities) {
        if (!isConfigurationValid() || vulnerabilities.isEmpty()) {
            if (!isConfigurationValid() && enabled) {
                log.warn("Yandex GPT is not properly configured. Skipping false positive filtering.");
            }
            return vulnerabilities;
        }

        log.info("Filtering false positives using AI agent");
        List<Vulnerability> filtered = new ArrayList<>();

        for (Vulnerability vuln : vulnerabilities) {
            try {
                if (!isFalsePositive(vuln)) {
                    filtered.add(vuln);
                } else {
                    log.debug("Filtered out false positive: {}", vuln.getTitle());
                }
            } catch (Exception e) {
                log.error("Error filtering false positive: {}", e.getMessage(), e);
                // Include vulnerability if filtering fails
                filtered.add(vuln);
            }
        }

        log.info("Filtered {} vulnerabilities, {} remaining", vulnerabilities.size() - filtered.size(), filtered.size());
        return filtered;
    }

    public String generateRecommendation(Vulnerability vulnerability) {
        if (!isConfigurationValid()) {
            if (!isConfigurationValid() && enabled) {
                log.warn("Yandex GPT is not properly configured. Using default recommendation.");
            }
            return vulnerability.getRecommendation();
        }

        String prompt = String.format(
            "Сгенерируй рекомендацию по исправлению уязвимости:\n\n" +
                "Категория OWASP: %s\n" +
                "Название: %s\n" +
                "Описание: %s\n" +
                "Endpoint: %s %s\n" +
                "Текущая рекомендация: %s\n\n" +
                "Дай улучшенную рекомендацию по исправлению этой уязвимости.",
            vulnerability.getOwaspCategory(),
            vulnerability.getTitle(),
            vulnerability.getDescription(),
            vulnerability.getMethod(),
            vulnerability.getEndpoint(),
            vulnerability.getRecommendation()
        );

        Request httpRequest = createYandexGptRequest(prompt).build();

        long startTime = System.currentTimeMillis();
        log.debug("Generating recommendation for vulnerability: {}", vulnerability.getTitle());

        try (Response response = aiAgentClient.newCall(httpRequest).execute()) {
            long duration = System.currentTimeMillis() - startTime;
            log.debug("Recommendation generation response: status={}, duration={}ms", response.code(), duration);

            if (response.isSuccessful() && response.body() != null) {
                String responseBody = response.body().string();
                String textResponse = extractResponseText(responseBody);
                if (textResponse != null && !textResponse.trim().isEmpty()) {
                    log.debug("AI generated recommendation: {} chars", textResponse.length());
                    return textResponse.trim();
                }
            } else {
                log.warn("Recommendation generation failed: status={}", response.code());
            }
        } catch (IOException e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("Recommendation generation error after {}ms: {}", duration, e.getMessage(), e);
        }

        return vulnerability.getRecommendation();
    }
    
    private boolean isConfigurationValid() {
        if (!enabled) {
            return false;
        }
        
        if (apiUrl == null || apiUrl.isEmpty()) {
            log.warn("Yandex GPT API URL is not configured");
            return false;
        }
        
        if (apiKey == null || apiKey.isEmpty()) {
            log.warn("Yandex GPT API key is not configured");
            return false;
        }
        
        if (folderId == null || folderId.isEmpty()) {
            log.warn("Yandex GPT folder ID is not configured");
            return false;
        }
        
        // Проверяем валидность URL
        try {
            HttpUrl.parse(apiUrl);
            return apiUrl.startsWith("http://") || apiUrl.startsWith("https://");
        } catch (Exception e) {
            log.error("Invalid Yandex GPT API URL: {}", apiUrl);
            return false;
        }
    }
    
    private Request.Builder createYandexGptRequest(String prompt) {
        
        // Формируем запрос к Yandex Cloud GPT API
        Map<String, Object> requestBody = new HashMap<>();
        
        // Определяем формат на основе URL
        if (apiUrl != null && apiUrl.contains("/v1/chat/completions")) {
            // Формат для /v1/chat/completions (OpenAI-совместимый API)
            requestBody.put("model", modelUri);
            // Для OpenAI-совместимого API используем параметры напрямую
            requestBody.put("temperature", 0.3);
            requestBody.put("max_tokens", 6000);
        } else {
            // Формат для /foundationModels/v1/completion (старый API)
            requestBody.put("modelUri", modelUri);
            Map<String, Object> completionOptions = new HashMap<>();
            completionOptions.put("temperature", 0.3);
            completionOptions.put("maxTokens", 6000);
            requestBody.put("completionOptions", completionOptions);
        }
        
        List<Map<String, String>> messages = new ArrayList<>();
        Map<String, String> message = new HashMap<>();
        message.put("role", "user");
        // Для /v1/chat/completions используется "content", для /foundationModels/v1/completion - "text"
        if (apiUrl != null && apiUrl.contains("/v1/chat/completions")) {
            message.put("content", prompt);
        } else {
            message.put("text", prompt);
        }
        messages.add(message);
        requestBody.put("messages", messages);
        
        String jsonBody;
        try {
            jsonBody = objectMapper.writeValueAsString(requestBody);
        } catch (Exception e) {
            log.error("Failed to serialize Yandex GPT request body", e);
            throw new RuntimeException("Failed to serialize request body", e);
        }
        
        Request.Builder builder = new Request.Builder()
                .url(apiUrl)
                .post(RequestBody.create(jsonBody, MediaType.get("application/json")));
        
        // Используем API key для аутентификации
        builder.header("Authorization", "Api-Key " + apiKey);
        builder.header("x-folder-id", folderId);
        
        return builder;
    }
    
    private String extractResponseText(String responseBody) {
        try {
            GptResponse response = objectMapper.readValue(responseBody, GptResponse.class);
            
            return response.getChoices().stream().map(it -> it.getMessage().getContent()).collect(Collectors.joining());
        } catch (Exception e) {
            log.error("Failed to parse Yandex GPT response: {}", e.getMessage(), e);
            log.debug("Response body: {}", responseBody.substring(0, Math.min(500, responseBody.length())));
        }
        return null;
    }
    
    private Vulnerability analyzeVulnerability(Vulnerability vulnerability) throws IOException {
        String prompt = String.format(
            "Проанализируй уязвимость безопасности API:\n\n" +
            "Категория OWASP: %s\n" +
            "Название: %s\n" +
            "Описание: %s\n" +
            "Endpoint: %s %s\n" +
            "Текущая критичность: %s\n\n" +
            "Оцени критичность уязвимости (CRITICAL, HIGH, MEDIUM, LOW) и дай рекомендацию по исправлению. " +
            "Ответь в формате JSON: {\"severity\": \"HIGH\", \"recommendation\": \"...\"}",
            vulnerability.getOwaspCategory(),
            vulnerability.getTitle(),
            vulnerability.getDescription(),
            vulnerability.getMethod(),
            vulnerability.getEndpoint(),
            vulnerability.getSeverity()
        );
        
        Request httpRequest = createYandexGptRequest(prompt).build();
        
        long startTime = System.currentTimeMillis();
        
        try (Response response = aiAgentClient.newCall(httpRequest).execute()) {
            int statusCode = response.code();
            
            if (response.isSuccessful() && response.body() != null) {
                String responseBody = response.body().string();
                
                String textResponse = extractResponseText(responseBody);
                if (textResponse != null) {
                    log.info("AI analysis response for vulnarability {}: \"{}\"", vulnerability, textResponse);
                    // Парсим JSON из ответа GPT
                    try {
                        Map<String, Object> result = objectMapper.readValue(textResponse, Map.class);
                        if (result.containsKey("severity")) {
                            String newSeverity = ((String) result.get("severity")).toUpperCase();
                            log.info("AI updated severity: {} -> {} for vulnerability: {}", 
                                vulnerability.getSeverity(), newSeverity, vulnerability.getTitle());
                            vulnerability.setSeverity(Vulnerability.Severity.valueOf(newSeverity));
                        }
                        if (result.containsKey("recommendation")) {
                            String recommendation = (String) result.get("recommendation");
                            log.info("Setting AI recommendation for vulnarability: {}", recommendation);
                            vulnerability.setRecommendation(recommendation);
                        }
                    } catch (Exception e) {
                        log.debug("Failed to parse GPT response as JSON, using as recommendation: {}", e.getMessage());
                        vulnerability.setRecommendation(textResponse);
                    }
                } else {
                    log.warn("Failed to extract text from AI response for vulnerability: {}", vulnerability.getTitle());
                }
            } else {
                String errorBody = response.body() != null ? response.body().string() : "No error body";
                log.error("AI analysis request failed: status={}, error={}, vulnerability={}", 
                    statusCode, errorBody.substring(0, Math.min(500, errorBody.length())), vulnerability.getTitle());
                
                // Если модель недоступна (500), логируем полный ответ для диагностики
                if (statusCode == 500) {
                    log.warn("Model {} may be unavailable. Consider using 'yandexgpt' instead.", modelUri);
                }
            }
        } catch (IOException e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("AI analysis request error after {}ms: {}, vulnerability={}", 
                duration, e.getMessage(), vulnerability.getTitle(), e);
        }
        
        return vulnerability;
    }
    
    private boolean isFalsePositive(Vulnerability vulnerability) throws IOException {
        String prompt = String.format(
            "Определи, является ли это ложным срабатыванием:\n\n" +
            "Категория OWASP: %s\n" +
            "Название: %s\n" +
            "Описание: %s\n" +
            "Endpoint: %s %s\n" +
            "Доказательства: %s\n\n" +
            "Ответь только 'true' или 'false' (без кавычек).",
            vulnerability.getOwaspCategory(),
            vulnerability.getTitle(),
            vulnerability.getDescription(),
            vulnerability.getMethod(),
            vulnerability.getEndpoint(),
            vulnerability.getEvidence()
        );
        
        Request httpRequest = createYandexGptRequest(prompt).build();
        
        long startTime = System.currentTimeMillis();
        log.debug("Checking false positive for vulnerability: {}", vulnerability.getTitle());
        
        try (Response response = aiAgentClient.newCall(httpRequest).execute()) {
            long duration = System.currentTimeMillis() - startTime;
            log.debug("False positive check response: status={}, duration={}ms", response.code(), duration);
            
            if (response.isSuccessful() && response.body() != null) {
                String responseBody = response.body().string();
                String textResponse = extractResponseText(responseBody);
                if (textResponse != null) {
                    boolean isFalsePositive = textResponse.trim().toLowerCase().contains("true");
                    log.debug("False positive check result: {} for vulnerability: {}", isFalsePositive, vulnerability.getTitle());
                    return isFalsePositive;
                }
            }
        } catch (IOException e) {
            long duration = System.currentTimeMillis() - startTime;
            log.error("False positive check error after {}ms: {}", duration, e.getMessage(), e);
        }
        
        return false;
    }
}

