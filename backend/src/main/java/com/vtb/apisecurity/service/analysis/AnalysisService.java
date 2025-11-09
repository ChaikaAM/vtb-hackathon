package com.vtb.apisecurity.service.analysis;

import com.vtb.apisecurity.model.ContractMismatch;
import com.vtb.apisecurity.model.ScanRequest;
import com.vtb.apisecurity.model.ScanResult;
import com.vtb.apisecurity.model.Vulnerability;
import com.vtb.apisecurity.service.ai.AiAgentService;
import com.vtb.apisecurity.service.analysis.analyzrs.ContractValidationService;
import com.vtb.apisecurity.service.analysis.analyzrs.dynamic.DynamicTestingService;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.StaticAnalysisService;
import com.vtb.apisecurity.service.auth.BankingAuthService;
import com.vtb.apisecurity.service.openapi.OpenApiParserService;
import com.vtb.apisecurity.service.report.ReportService;
import io.swagger.v3.oas.models.OpenAPI;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Slf4j
@AllArgsConstructor
public class AnalysisService {
    
    private final OpenApiParserService parserService;
    private final StaticAnalysisService staticAnalysisService;
    private final DynamicTestingService dynamicTestingService;
    private final ContractValidationService contractValidationService;
    private final AiAgentService aiAgentService;
    private final ReportService reportService;
    private final BankingAuthService bankingAuthService;
    private final ScanHistoryService scanHistoryService;
    
    public ScanResult startAnalysis(ScanRequest request) {
        String scanId = UUID.randomUUID().toString();
        LocalDateTime startTime = LocalDateTime.now();
        
        ScanResult result = ScanResult.builder()
                .scanId(scanId)
                .openApiUrl(request.getOpenApiUrl())
                .apiBaseUrl(request.getApiBaseUrl())
                .status(ScanResult.ScanStatus.RUNNING)
                .startTime(startTime)
                .vulnerabilities(new ArrayList<>())
                .contractMismatches(new ArrayList<>())
                .endpointAnalyses(new ArrayList<>())
                .build();
        
        // Save initial result
        reportService.saveInMemory(result);
        
        // Create history entry
        scanHistoryService.createHistory(request, scanId);
        
        // Start async analysis
        Thread analysisThread = new Thread(() -> {
            try {
                analyzeInternal(request, result);
            } catch (InterruptedException e) {
                log.info("Analysis interrupted: scanId={}", scanId);
                result.setStatus(ScanResult.ScanStatus.CANCELLED);
                result.setEndTime(LocalDateTime.now());
                if (result.getStartTime() != null) {
                    result.setDurationMs(java.time.Duration.between(
                            result.getStartTime(), result.getEndTime()).toMillis());
                }
                reportService.saveInMemory(result);
                scanHistoryService.updateHistory(scanId, result);
            }
        });
        
        analysisThread.setName("Analysis-" + scanId);
        scanHistoryService.registerRunningScan(scanId, analysisThread);
        analysisThread.start();
        
        return result;
    }
    
    private void analyzeInternal(ScanRequest request, ScanResult result) throws InterruptedException {
        String scanId = result.getScanId();
        LocalDateTime startTime = result.getStartTime();
        
        try {
            log.info("Starting analysis scanId={}, openApiUrl={}, apiBaseUrl={}", 
                    scanId, request.getOpenApiUrl(), request.getApiBaseUrl());
            
            // Check for interruption
            if (Thread.currentThread().isInterrupted()) {
                throw new InterruptedException("Analysis cancelled");
            }
            
            // Parse OpenAPI specification
            OpenAPI openAPI = parserService.parseFromUrl(request.getOpenApiUrl());
            
            // Count endpoints
            int totalEndpoints = countEndpoints(openAPI);
            result.setTotalEndpoints(totalEndpoints);
            reportService.saveInMemory(result);
            
            ScanRequest.ScanOptions options = request.getOptions() != null ? 
                    request.getOptions() : new ScanRequest.ScanOptions();
            
            // Static analysis
            if (options.isEnableStaticAnalysis()) {
                if (Thread.currentThread().isInterrupted()) {
                    throw new InterruptedException("Analysis cancelled");
                }
                log.info("Running static analysis");
                List<Vulnerability> staticVulnerabilities = staticAnalysisService.analyze(openAPI);
                result.getVulnerabilities().addAll(staticVulnerabilities);
                reportService.saveInMemory(result);
            }
            
            // Get access token for dynamic analysis
            String authToken = null;
            if (options.isEnableDynamicTesting() || options.isEnableContractValidation()) {
                if (Thread.currentThread().isInterrupted()) {
                    throw new InterruptedException("Analysis cancelled");
                }
                try {
                    authToken = bankingAuthService.getAccessToken();
                    log.info("Obtained access token for dynamic analysis");
                } catch (Exception e) {
                    log.error("Failed to obtain access token: {}", e.getMessage(), e);
                    // Continue without token - some tests might still work
                }
            }
            
            // Dynamic testing
            if (options.isEnableDynamicTesting()) {
                if (Thread.currentThread().isInterrupted()) {
                    throw new InterruptedException("Analysis cancelled");
                }
                log.info("Running dynamic testing");
                List<Vulnerability> dynamicVulnerabilities = dynamicTestingService.test(
                        openAPI, request.getApiBaseUrl(), authToken);
                result.getVulnerabilities().addAll(dynamicVulnerabilities);
                reportService.saveInMemory(result);
            }
            
            // Contract validation
            if (options.isEnableContractValidation()) {
                if (Thread.currentThread().isInterrupted()) {
                    throw new InterruptedException("Analysis cancelled");
                }
                log.info("Running contract validation");
                List<ContractMismatch> mismatches = contractValidationService.validate(
                        openAPI, request.getApiBaseUrl(), authToken);
                result.setContractMismatches(mismatches);
                reportService.saveInMemory(result);
            }
            
            // AI analysis
            if (options.isEnableAiAnalysis()) {
                if (Thread.currentThread().isInterrupted()) {
                    throw new InterruptedException("Analysis cancelled");
                }
                log.info("Running AI analysis");
                result.setVulnerabilities(aiAgentService.filterFalsePositives(result.getVulnerabilities()));
                result.setVulnerabilities(aiAgentService.analyzeVulnerabilities(result.getVulnerabilities()));
                
                // Generate recommendations
                result.getVulnerabilities().forEach(vuln -> {
                    if (vuln.getRecommendation() == null || vuln.getRecommendation().isEmpty()) {
                        vuln.setRecommendation(aiAgentService.generateRecommendation(vuln));
                    }
                });
                reportService.saveInMemory(result);
            }
            
            // Calculate statistics
            calculateStatistics(result);
            
            result.setStatus(ScanResult.ScanStatus.COMPLETED);
            result.setEndTime(LocalDateTime.now());
            result.setDurationMs(java.time.Duration.between(startTime, result.getEndTime()).toMillis());
            
            reportService.saveInMemory(result);
            scanHistoryService.updateHistory(scanId, result);
            
            log.info("Analysis completed scanId={}, vulnerabilities={}, mismatches={}", 
                    scanId, result.getVulnerabilities().size(), result.getContractMismatches().size());
            
        } catch (InterruptedException e) {
            throw e;
        } catch (Exception e) {
            log.error("Error during analysis scanId={}: {}", scanId, e.getMessage(), e);
            result.setStatus(ScanResult.ScanStatus.FAILED);
            result.setEndTime(LocalDateTime.now());
            result.setSummary("Analysis failed: " + e.getMessage());
            reportService.saveInMemory(result);
            scanHistoryService.updateHistory(scanId, result);
        }
    }
    
    private int countEndpoints(OpenAPI openAPI) {
        if (openAPI.getPaths() == null) {
            return 0;
        }
        
        int count = 0;
        for (io.swagger.v3.oas.models.PathItem pathItem : openAPI.getPaths().values()) {
            if (pathItem.getGet() != null) count++;
            if (pathItem.getPost() != null) count++;
            if (pathItem.getPut() != null) count++;
            if (pathItem.getDelete() != null) count++;
            if (pathItem.getPatch() != null) count++;
        }
        return count;
    }
    
    private void calculateStatistics(ScanResult result) {
        // Count vulnerabilities by severity
        Map<String, Integer> vulnCounts = result.getVulnerabilities().stream()
                .collect(Collectors.groupingBy(
                        v -> v.getSeverity().name(),
                        Collectors.collectingAndThen(Collectors.counting(), Long::intValue)
                ));
        result.setVulnerabilityCounts(vulnCounts);
        
        // Count by OWASP category
        Map<String, Integer> categoryCounts = result.getVulnerabilities().stream()
                .collect(Collectors.groupingBy(
                        Vulnerability::getOwaspCategory,
                        Collectors.collectingAndThen(Collectors.counting(), Long::intValue)
                ));
        
        // Calculate tested endpoints
        Set<String> testedEndpoints = new HashSet<>();
        result.getVulnerabilities().forEach(v -> {
            if (v.getEndpoint() != null) {
                testedEndpoints.add(v.getEndpoint());
            }
        });
        result.setTestedEndpoints(testedEndpoints.size());
        
        // Generate summary
        StringBuilder summary = new StringBuilder();
        summary.append("Analysis completed. Found ");
        summary.append(result.getVulnerabilities().size());
        summary.append(" vulnerabilities and ");
        summary.append(result.getContractMismatches().size());
        summary.append(" contract mismatches across ");
        summary.append(result.getTotalEndpoints());
        summary.append(" endpoints.");
        
        result.setSummary(summary.toString());
    }
}

