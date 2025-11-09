package com.vtb.apisecurity.service.analysis.analyzrs.dynamic;

import com.vtb.apisecurity.model.Vulnerability;
import com.vtb.apisecurity.service.analysis.analyzrs.dynamic.payload.PayloadGenerator;
import com.vtb.apisecurity.service.analysis.analyzrs.dynamic.detectors.BolaDetector;
import com.vtb.apisecurity.service.analysis.analyzrs.dynamic.detectors.BusinessFlowDetector;
import com.vtb.apisecurity.service.analysis.analyzrs.dynamic.detectors.InjectionDetector;
import com.vtb.apisecurity.service.analysis.analyzrs.dynamic.detectors.RateLimitDetector;
import com.vtb.apisecurity.service.analysis.analyzrs.dynamic.detectors.ThirdPartyConsumptionDetector;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.PathItem;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
@Slf4j
@AllArgsConstructor
public class DynamicTestingService {

    private final BolaDetector bolaDetector;
    private final InjectionDetector injectionDetector;
    private final RateLimitDetector rateLimitDetector;
    private final BusinessFlowDetector businessFlowDetector;
    private final ThirdPartyConsumptionDetector thirdPartyConsumptionDetector;
    
    public List<Vulnerability> test(OpenAPI openAPI, String apiBaseUrl, String authToken) {
        log.info("Starting dynamic testing for API: {}", apiBaseUrl);
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        if (openAPI.getPaths() == null) {
            return vulnerabilities;
        }
        
        // Normalize base URL
        String baseUrl = apiBaseUrl.endsWith("/") ? apiBaseUrl.substring(0, apiBaseUrl.length() - 1) : apiBaseUrl;
        
        openAPI.getPaths().forEach((path, pathItem) -> {
            try {
                List<Vulnerability> pathVulnerabilities = testPath(path, pathItem, baseUrl, authToken, openAPI);
                vulnerabilities.addAll(pathVulnerabilities);
            } catch (Exception e) {
                log.error("Error testing path {}: {}", path, e.getMessage(), e);
            }
        });
        
        log.info("Dynamic testing completed. Found {} vulnerabilities", vulnerabilities.size());
        return vulnerabilities;
    }
    
    private List<Vulnerability> testPath(String path, PathItem pathItem, String baseUrl, 
                                        String authToken, OpenAPI openAPI) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        // Test GET endpoints for BOLA
        if (pathItem.getGet() != null && path.contains("{")) {
            vulnerabilities.addAll(bolaDetector.test(path, "GET", baseUrl, authToken));
        }
        
        // Test for injection vulnerabilities
        if (pathItem.getGet() != null) {
            vulnerabilities.addAll(injectionDetector.test(path, pathItem.getGet(), baseUrl, authToken));
        }
        if (pathItem.getPost() != null) {
            vulnerabilities.addAll(injectionDetector.test(path, pathItem.getPost(), baseUrl, authToken));
        }
        
        // Test rate limiting
        if (pathItem.getPost() != null || pathItem.getPut() != null || pathItem.getDelete() != null) {
            String method = pathItem.getPost() != null ? "POST" : 
                           pathItem.getPut() != null ? "PUT" : "DELETE";
            vulnerabilities.addAll(rateLimitDetector.test(path, method, baseUrl, authToken));
        }
        
        // Test business flow automation (API6)
        if (pathItem.getPost() != null) {
            vulnerabilities.addAll(businessFlowDetector.test(path, "POST", baseUrl, authToken));
        }
        
        // Test third-party consumption (API10)
        if (pathItem.getPost() != null) {
            vulnerabilities.addAll(thirdPartyConsumptionDetector.test(path, "POST", baseUrl, authToken));
        }
        
        return vulnerabilities;
    }
}

