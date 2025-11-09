package com.vtb.apisecurity.service.openapi;

import com.vtb.apisecurity.exception.AnalysisException;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.models.ParseOptions;
import io.swagger.v3.parser.core.models.SwaggerParseResult;
import lombok.extern.slf4j.Slf4j;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
public class OpenApiParserService {

    private final OkHttpClient httpClient;
    private final OpenAPIV3Parser parser;

    public OpenApiParserService() {
        this.httpClient = new OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .build();
        this.parser = new OpenAPIV3Parser();
    }
    
    private void logHeaders(Request request, String type) {
        log.debug("[OPENAPI_PARSER] {} Headers:", type);
        request.headers().forEach(pair -> {
            log.debug("[OPENAPI_PARSER]   {}: {}", pair.getFirst(), pair.getSecond());
        });
    }
    
    private void logHeaders(Response response, String type) {
        log.debug("[OPENAPI_PARSER] {} Headers:", type);
        response.headers().forEach(pair -> {
            log.debug("[OPENAPI_PARSER]   {}: {}", pair.getFirst(), pair.getSecond());
        });
    }
    
    private void logRequest(Request request) {
        log.info("[OPENAPI_PARSER] Request: GET {}", request.url());
        logHeaders(request, "Request");
    }
    
    private void logResponse(Response response, String content) {
        log.info("[OPENAPI_PARSER] Response: GET {} - Status: {}", response.request().url(), response.code());
        logHeaders(response, "Response");
        if (content != null && !content.isEmpty()) {
            String truncatedContent = content.length() > 1000 ? content.substring(0, 1000) + "... (truncated)" : content;
            log.info("[OPENAPI_PARSER] Response Body (first 1000 chars): {}", truncatedContent);
        } else {
            log.debug("[OPENAPI_PARSER] Response Body: (empty)");
        }
    }

    public OpenAPI parseFromUrl(String url) throws IOException {
        log.info("Fetching OpenAPI spec from: {}", url);

        Request request = new Request.Builder()
            .url(url)
            .build();
        
        // Логирование запроса
        logRequest(request);

        try (Response response = httpClient.newCall(request).execute()) {
            String content = response.body() != null ? response.body().string() : "";
            
            // Логирование ответа
            logResponse(response, content);
            
            if (!response.isSuccessful()) {
                throw new AnalysisException("Failed to fetch OpenAPI spec: " + response.code());
            }

            return parseFromContent(content);
        }
    }

    public OpenAPI parseFromContent(String content) {
        log.info("Parsing OpenAPI specification");

        ParseOptions options = new ParseOptions();
        options.setResolve(true);
        options.setFlatten(true);

        SwaggerParseResult result = parser.readContents(content, null, options);

        if (result.getMessages() != null && !result.getMessages().isEmpty()) {
            log.warn("OpenAPI parsing warnings: {}", result.getMessages());
        }

        if (result.getOpenAPI() == null) {
            throw new AnalysisException("Failed to parse OpenAPI specification: " + result.getMessages());
        }

        return result.getOpenAPI();
    }
}

