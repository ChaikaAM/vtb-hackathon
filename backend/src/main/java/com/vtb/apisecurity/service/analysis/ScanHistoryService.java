package com.vtb.apisecurity.service.analysis;

import com.vtb.apisecurity.model.ScanHistory;
import com.vtb.apisecurity.model.ScanRequest;
import com.vtb.apisecurity.model.ScanResult;
import com.vtb.apisecurity.service.report.ReportService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class ScanHistoryService {
    
    private final Map<String, ScanHistory> scanHistory = new ConcurrentHashMap<>();
    private final Map<String, Thread> runningScans = new ConcurrentHashMap<>();
    private final ReportService reportService;
    
    public ScanHistory createHistory(ScanRequest request, String scanId) {
        String bankName = extractBankName(request.getOpenApiUrl());
        
        ScanHistory history = ScanHistory.builder()
                .scanId(scanId)
                .openApiUrl(request.getOpenApiUrl())
                .apiBaseUrl(request.getApiBaseUrl())
                .bankName(bankName)
                .startTime(LocalDateTime.now())
                .status(ScanResult.ScanStatus.RUNNING)
                .options(request.getOptions() != null ? request.getOptions() : new ScanRequest.ScanOptions())
                .build();
        
        scanHistory.put(scanId, history);
        log.info("Created scan history entry: scanId={}, bankName={}", scanId, bankName);
        return history;
    }
    
    public void updateHistory(String scanId, ScanResult result) {
        ScanHistory history = scanHistory.get(scanId);
        if (history != null) {
            history.setStatus(result.getStatus());
            history.setEndTime(result.getEndTime());
            history.setDurationMs(result.getDurationMs());
            log.info("Updated scan history: scanId={}, status={}", scanId, result.getStatus());
        }
    }
    
    public List<ScanHistory> getAllHistory() {
        return scanHistory.values().stream()
                .peek(history -> {
                    // Для выполняющихся анализов вычисляем текущую длительность
                    if (history.getStatus() == ScanResult.ScanStatus.RUNNING && history.getDurationMs() == null) {
                        history.setDurationMs(history.getCurrentDurationMs());
                    }
                })
                .sorted(Comparator.comparing(ScanHistory::getStartTime).reversed())
                .collect(Collectors.toList());
    }
    
    public Optional<ScanHistory> getHistory(String scanId) {
        return Optional.ofNullable(scanHistory.get(scanId));
    }
    
    public boolean cancelScan(String scanId) {
        Thread scanThread = runningScans.get(scanId);
        if (scanThread != null && scanThread.isAlive()) {
            scanThread.interrupt();
            ScanHistory history = scanHistory.get(scanId);
            if (history != null) {
                history.setStatus(ScanResult.ScanStatus.CANCELLED);
                history.setEndTime(LocalDateTime.now());
                if (history.getStartTime() != null) {
                    history.setDurationMs(java.time.Duration.between(
                            history.getStartTime(), history.getEndTime()).toMillis());
                }
            }
            runningScans.remove(scanId);
            log.info("Cancelled scan: scanId={}", scanId);
            return true;
        }
        return false;
    }
    
    public boolean deleteScan(String scanId) {
        runningScans.remove(scanId);
        ScanHistory removed = scanHistory.remove(scanId);
        if (removed != null) {
            reportService.deleteScanResult(scanId);
            log.info("Deleted scan history: scanId={}", scanId);
            return true;
        }
        return false;
    }
    
    public void registerRunningScan(String scanId, Thread thread) {
        runningScans.put(scanId, thread);
    }
    
    private String extractBankName(String openApiUrl) {
        if (openApiUrl == null) {
            return "Unknown";
        }
        
        if (openApiUrl.contains("vbank")) {
            return "VBank";
        } else if (openApiUrl.contains("abank")) {
            return "ABank";
        } else if (openApiUrl.contains("sbank")) {
            return "SBank";
        }
        
        // Try to extract from URL
        try {
            java.net.URL url = new java.net.URL(openApiUrl);
            String host = url.getHost();
            if (host.contains(".")) {
                String[] parts = host.split("\\.");
                if (parts.length > 0) {
                    return parts[0].substring(0, 1).toUpperCase() + parts[0].substring(1);
                }
            }
        } catch (Exception e) {
            // Ignore
        }
        
        return "Unknown";
    }
}

