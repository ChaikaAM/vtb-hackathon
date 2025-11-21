package com.vtb.apisecurity.service.analysis;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

import com.vtb.apisecurity.model.ContractMismatch;
import com.vtb.apisecurity.model.CustomCheckResult;
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

@Service
@Slf4j
@AllArgsConstructor
public class AnalysisService {
    
    private final OpenApiParserService parserService;
    private final StaticAnalysisService staticAnalysisService;
    private final DynamicTestingService dynamicTestingService;
    private final ContractValidationService contractValidationService;
    private final AiAgentService aiAgentService;
    private final CustomCheckService customCheckService;
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
                .customCheckResults(new ArrayList<>())
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
            log.info("OpenAPI parsed successfully, paths count: {}", 
                    openAPI.getPaths() != null ? openAPI.getPaths().size() : 0);
            
            // Count endpoints
            int totalEndpoints = countEndpoints(openAPI);
            result.setTotalEndpoints(totalEndpoints);
            log.info("Total endpoints counted: {}", totalEndpoints);
            reportService.saveInMemory(result);
            
            ScanRequest.ScanOptions options = request.getOptions() != null ? 
                    request.getOptions() : new ScanRequest.ScanOptions();
            
            log.info("[SCAN_OPTIONS] Request options is null: {}", request.getOptions() == null);
            log.info("[SCAN_OPTIONS] enableStaticAnalysis={}, enableDynamicTesting={}, enableContractValidation={}, enableAiAnalysis={}, customChecks={}", 
                    options.isEnableStaticAnalysis(), 
                    options.isEnableDynamicTesting(), 
                    options.isEnableContractValidation(), 
                    options.isEnableAiAnalysis(),
                    options.getCustomChecks() != null ? options.getCustomChecks().size() : "null");
            
            // Static analysis
            if (options.isEnableStaticAnalysis()) {
                if (Thread.currentThread().isInterrupted()) {
                    throw new InterruptedException("Analysis cancelled");
                }
                log.info("[STATIC_ANALYSIS] Starting static analysis");
                List<Vulnerability> staticVulnerabilities = staticAnalysisService.analyze(openAPI);
                log.info("[STATIC_ANALYSIS] Completed, found {} vulnerabilities", staticVulnerabilities.size());
                result.getVulnerabilities().addAll(staticVulnerabilities);
                reportService.saveInMemory(result);
            } else {
                log.info("[STATIC_ANALYSIS] Skipped (disabled)");
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
                log.info("[DYNAMIC_TESTING] Starting dynamic testing");
                List<Vulnerability> dynamicVulnerabilities = dynamicTestingService.test(
                        openAPI, request.getApiBaseUrl(), authToken);
                log.info("[DYNAMIC_TESTING] Completed, found {} vulnerabilities", dynamicVulnerabilities.size());
                result.getVulnerabilities().addAll(dynamicVulnerabilities);
                reportService.saveInMemory(result);
            } else {
                log.info("[DYNAMIC_TESTING] Skipped (disabled)");
            }
            
            // Contract validation
            if (options.isEnableContractValidation()) {
                if (Thread.currentThread().isInterrupted()) {
                    throw new InterruptedException("Analysis cancelled");
                }
                log.info("[CONTRACT_VALIDATION] Starting contract validation");
                List<ContractMismatch> mismatches = contractValidationService.validate(
                        openAPI, request.getApiBaseUrl(), authToken);
                log.info("[CONTRACT_VALIDATION] Completed, found {} mismatches", mismatches.size());
                result.setContractMismatches(mismatches);
                reportService.saveInMemory(result);
            } else {
                log.info("[CONTRACT_VALIDATION] Skipped (disabled)");
            }
            
            // AI analysis
            if (options.isEnableAiAnalysis()) {
                if (Thread.currentThread().isInterrupted()) {
                    throw new InterruptedException("Analysis cancelled");
                }
                log.info("[AI_ANALYSIS] Starting AI analysis, vulnerabilities before: {}", result.getVulnerabilities().size());
                result.setVulnerabilities(aiAgentService.filterFalsePositives(result.getVulnerabilities()));
                log.info("[AI_ANALYSIS] After filtering false positives: {}", result.getVulnerabilities().size());
                result.setVulnerabilities(aiAgentService.analyzeVulnerabilities(result.getVulnerabilities()));
                log.info("[AI_ANALYSIS] After AI analysis: {}", result.getVulnerabilities().size());
                
                // Generate recommendations
                result.getVulnerabilities().forEach(vuln -> {
                    if (vuln.getRecommendation() == null || vuln.getRecommendation().isEmpty()) {
                        vuln.setRecommendation(aiAgentService.generateRecommendation(vuln));
                    }
                });
                reportService.saveInMemory(result);
                log.info("[AI_ANALYSIS] Completed");
            } else {
                log.info("[AI_ANALYSIS] Skipped (disabled)");
            }
            
            // Custom checks
            log.info("Checking custom checks: options.getCustomChecks()={}", 
                    options.getCustomChecks() != null ? options.getCustomChecks().size() : "null");
            
            if (options.getCustomChecks() != null && !options.getCustomChecks().isEmpty()) {
                if (Thread.currentThread().isInterrupted()) {
                    throw new InterruptedException("Analysis cancelled");
                }
                
                log.info("Found {} custom checks in request, filtering enabled ones", options.getCustomChecks().size());
                
                List<ScanRequest.CustomCheck> enabledChecks = options.getCustomChecks().stream()
                        .filter(check -> {
                            boolean enabled = check.isEnabled();
                            boolean hasName = check.getName() != null && !check.getName().trim().isEmpty();
                            boolean hasPrompt = check.getPrompt() != null && !check.getPrompt().trim().isEmpty();
                            
                            if (!enabled) {
                                log.info("Custom check '{}' skipped: disabled", check.getName());
                            }
                            if (!hasName) {
                                log.info("Custom check skipped: missing name (ID: {})", check.getId());
                            }
                            if (!hasPrompt) {
                                log.info("Custom check '{}' skipped: missing prompt", check.getName());
                            }
                            
                            return enabled && hasName && hasPrompt;
                        })
                        .collect(java.util.stream.Collectors.toList());
                
                log.info("After filtering: {} enabled custom checks ready to execute", enabledChecks.size());
                
                if (!enabledChecks.isEmpty()) {
                    log.info("Running {} custom checks", enabledChecks.size());
                    
                    List<CustomCheckResult> customResults = new ArrayList<>();
                    for (ScanRequest.CustomCheck check : enabledChecks) {
                        if (Thread.currentThread().isInterrupted()) {
                            throw new InterruptedException("Analysis cancelled");
                        }
                        try {
                            CustomCheckResult checkResult = customCheckService.executeCheck(
                                    check, openAPI, request.getApiBaseUrl(), authToken);
                            customResults.add(checkResult);
                            
                            // Если проверка нашла уязвимости, добавляем их в общий список
                            if (checkResult.getVulnerabilities() != null && !checkResult.getVulnerabilities().isEmpty()) {
                                result.getVulnerabilities().addAll(checkResult.getVulnerabilities());
                            }
                        } catch (Exception e) {
                            log.error("Error executing custom check {}: {}", check.getName(), e.getMessage(), e);
                            // Создаем результат с ошибкой
                            customResults.add(CustomCheckResult.builder()
                                    .checkId(check.getId())
                                    .checkName(check.getName())
                                    .category(check.getCategory())
                                    .status(CustomCheckResult.CheckStatus.ERROR)
                                    .result("Ошибка выполнения проверки: " + e.getMessage())
                                    .executedAt(java.time.LocalDateTime.now())
                                    .build());
                        }
                    }
                    result.setCustomCheckResults(customResults);
                    reportService.saveInMemory(result);
                    log.info("Custom checks completed: {} results saved", customResults.size());
                } else {
                    log.warn("No enabled custom checks found after filtering. Total checks: {}, Enabled: 0", 
                            options.getCustomChecks().size());
                }
            } else {
                log.info("Custom checks not executed: options.getCustomChecks() is null or empty");
            }
            
            // Calculate statistics
            calculateStatistics(result);
            
            result.setStatus(ScanResult.ScanStatus.COMPLETED);
            result.setEndTime(LocalDateTime.now());
            result.setDurationMs(java.time.Duration.between(startTime, result.getEndTime()).toMillis());
            
            reportService.saveInMemory(result);
            scanHistoryService.updateHistory(scanId, result);
            
            log.info("Analysis completed scanId={}, vulnerabilities={}, mismatches={}, customChecks={}", 
                    scanId, result.getVulnerabilities().size(), result.getContractMismatches().size(),
                    result.getCustomCheckResults() != null ? result.getCustomCheckResults().size() : 0);
            
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

