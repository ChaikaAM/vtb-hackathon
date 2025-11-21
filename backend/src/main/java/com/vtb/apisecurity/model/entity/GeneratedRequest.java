package com.vtb.apisecurity.model.entity;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class GeneratedRequest {
    private String method;
    private String path;
    private Map<String, Object> pathParameters;
    private Map<String, Object> queryParameters;
    private Map<String, String> headers;
    private Object body; // JSON object или null
    private String description;
    private String extractIdFrom; // JSONPath для извлечения ID из ответа
    
    /**
     * Формирует полный URL с path и query параметрами
     */
    public String buildUrl(String baseUrl) {
        String normalizedBaseUrl = baseUrl.endsWith("/") ? 
            baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        
        String url = normalizedBaseUrl + replacePathParameters(path);
        
        if (queryParameters != null && !queryParameters.isEmpty()) {
            StringBuilder query = new StringBuilder();
            queryParameters.forEach((key, value) -> {
                if (value != null) {
                    if (query.length() > 0) query.append("&");
                    query.append(key).append("=").append(encodeValue(value.toString()));
                }
            });
            if (query.length() > 0) {
                url += "?" + query.toString();
            }
        }
        
        return url;
    }
    
    private String replacePathParameters(String path) {
        String result = path;
        if (pathParameters != null) {
            for (Map.Entry<String, Object> entry : pathParameters.entrySet()) {
                result = result.replace("{" + entry.getKey() + "}", entry.getValue().toString());
            }
        }
        return result;
    }
    
    private String encodeValue(String value) {
        try {
            return java.net.URLEncoder.encode(value, "UTF-8");
        } catch (Exception e) {
            return value;
        }
    }
}

