package com.vtb.apisecurity.service.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class BankingAuthService {
    
    private final OkHttpClient httpClient;
    private final String authUrl;
    private final String clientId;
    private final String clientSecret;
    private final ObjectMapper objectMapper;
    
    private String cachedToken;
    private long tokenExpiresAt;
    
    public BankingAuthService(
            @Value("${banking.auth.url:https://vbank.open.bankingapi.ru/auth/bank-token}") String authUrl,
            @Value("${banking.auth.client-id}") String clientId,
            @Value("${banking.auth.client-secret}") String clientSecret) {
        this.authUrl = authUrl;
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.objectMapper = new ObjectMapper();
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .build();
    }
    
    private void logHeaders(Request request, String type) {
        log.debug("[BANKING_AUTH] {} Headers:", type);
        request.headers().forEach(pair -> {
            log.debug("[BANKING_AUTH]   {}: {}", pair.getFirst(), pair.getSecond());
        });
    }
    
    private void logHeaders(Response response, String type) {
        log.debug("[BANKING_AUTH] {} Headers:", type);
        response.headers().forEach(pair -> {
            log.debug("[BANKING_AUTH]   {}: {}", pair.getFirst(), pair.getSecond());
        });
    }
    
    private void logRequest(Request request) {
        log.info("[BANKING_AUTH] Request: POST {}", request.url());
        logHeaders(request, "Request");
        // Логируем URL с параметрами, но скрываем client_secret
        HttpUrl url = request.url();
        String logUrl = url.toString().replaceAll("client_secret=[^&]+", "client_secret=***");
        log.info("[BANKING_AUTH] Request URL: {}", logUrl);
    }
    
    private void logResponse(Response response, String responseBody) {
        log.info("[BANKING_AUTH] Response: Status: {}", response.code());
        logHeaders(response, "Response");
        if (responseBody != null && !responseBody.isEmpty()) {
            // Скрываем access_token в логах
            String logBody = responseBody.replaceAll("\"access_token\"\\s*:\\s*\"[^\"]+\"", "\"access_token\":\"***\"");
            String truncatedBody = logBody.length() > 500 ? logBody.substring(0, 500) + "... (truncated)" : logBody;
            log.info("[BANKING_AUTH] Response Body: {}", truncatedBody);
        } else {
            log.debug("[BANKING_AUTH] Response Body: (empty)");
        }
    }
    
    /**
     * Получает токен доступа из банковского API.
     * Использует кэширование для избежания лишних запросов.
     * 
     * @return JWT токен доступа
     * @throws RuntimeException если не удалось получить токен
     */
    public String getAccessToken() {
        // Проверяем, есть ли валидный кэшированный токен
        if (cachedToken != null && System.currentTimeMillis() < tokenExpiresAt) {
            log.debug("Using cached access token");
            return cachedToken;
        }
        
        log.info("Requesting new access token from banking API");
        
        try {
            // Формируем URL с параметрами
            HttpUrl url = HttpUrl.parse(authUrl).newBuilder()
                    .addQueryParameter("client_id", clientId)
                    .addQueryParameter("client_secret", clientSecret)
                    .build();
            
            // Создаем POST запрос с пустым телом
            RequestBody body = RequestBody.create("", MediaType.get("application/json"));
            Request request = new Request.Builder()
                    .url(url)
                    .post(body)
                    .header("Accept", "application/json")
                    .build();
            
            // Логирование запроса
            logRequest(request);
            
            // Выполняем запрос
            try (Response response = httpClient.newCall(request).execute()) {
                String responseBody = response.body() != null ? response.body().string() : "";
                
                // Логирование ответа
                logResponse(response, responseBody);
                
                if (!response.isSuccessful()) {
                    throw new RuntimeException("Failed to get access token. Status: " + response.code() + 
                            ", Message: " + responseBody);
                }
                
                JsonNode jsonResponse = objectMapper.readTree(responseBody);
                
                String accessToken = jsonResponse.get("access_token").asText();
                int expiresIn = jsonResponse.has("expires_in") ? 
                        jsonResponse.get("expires_in").asInt() : 86400; // По умолчанию 24 часа
                
                // Кэшируем токен с небольшим запасом (минус 5 минут от expires_in)
                cachedToken = accessToken;
                tokenExpiresAt = System.currentTimeMillis() + ((expiresIn - 300) * 1000L);
                
                log.info("Successfully obtained access token. Expires in {} seconds", expiresIn);
                return accessToken;
            }
        } catch (IOException e) {
            log.error("Error getting access token: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to get access token: " + e.getMessage(), e);
        }
    }
    
    /**
     * Сбрасывает кэшированный токен, принуждая получить новый при следующем запросе.
     */
    public void invalidateToken() {
        log.info("Invalidating cached access token");
        cachedToken = null;
        tokenExpiresAt = 0;
    }
}

