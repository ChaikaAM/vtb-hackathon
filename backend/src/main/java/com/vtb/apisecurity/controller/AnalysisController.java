package com.vtb.apisecurity.controller;

import com.vtb.apisecurity.model.ScanRequest;
import com.vtb.apisecurity.model.ScanResult;
import com.vtb.apisecurity.service.analysis.AnalysisService;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/analysis")
@Slf4j
@AllArgsConstructor
public class AnalysisController {

    private final AnalysisService analysisService;

    // TODO - RateLimiter (10 req/s)
    @PostMapping("/scan")
    public ScanResult startScan(@Valid @RequestBody ScanRequest request) {
        log.info("Received scan request: openApiUrl={}, apiBaseUrl={}",
            request.getOpenApiUrl(), request.getApiBaseUrl());

        return analysisService.startAnalysis(request);
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        Map<String, String> response = new HashMap<>();
        response.put("status", "UP");
        return ResponseEntity.ok(response);
    }

}

