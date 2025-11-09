package com.vtb.apisecurity.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScanResult {
    private String scanId;
    private String openApiUrl;
    private String apiBaseUrl;
    private ScanStatus status;
    private LocalDateTime startTime;
    private LocalDateTime endTime;
    private Long durationMs;
    
    // Results
    private List<Vulnerability> vulnerabilities = new ArrayList<>();
    private List<ContractMismatch> contractMismatches = new ArrayList<>();
    private List<EndpointAnalysis> endpointAnalyses = new ArrayList<>();
    
    // Statistics
    private Map<String, Integer> vulnerabilityCounts;
    private int totalEndpoints;
    private int testedEndpoints;
    private int passedEndpoints;
    private int failedEndpoints;
    
    // Summary
    private String summary;
    private Map<String, Object> metadata;
    
    public enum ScanStatus {
        PENDING, RUNNING, COMPLETED, FAILED, CANCELLED
    }
}

