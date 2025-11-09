package com.vtb.apisecurity.controller;

import com.vtb.apisecurity.model.ScanHistory;
import com.vtb.apisecurity.model.ScanResult;
import com.vtb.apisecurity.service.analysis.ScanHistoryService;
import com.vtb.apisecurity.service.report.ReportService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/analysis/history")
@Slf4j
@AllArgsConstructor
public class ScanHistoryController {

    private final ScanHistoryService scanHistoryService;
    private final ReportService reportService;

    @GetMapping
    public List<ScanHistory> getAllHistory() {
        return scanHistoryService.getAllHistory();
    }

    @GetMapping("/{scanId}")
    public ResponseEntity<ScanHistory> getHistory(@PathVariable String scanId) {
        Optional<ScanHistory> history = scanHistoryService.getHistory(scanId);
        return history.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/{scanId}/status")
    public ResponseEntity<ScanResult> getStatus(@PathVariable String scanId) {
        Optional<ScanResult> result = reportService.getScanResult(scanId);
        return result.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/{scanId}/cancel")
    public ResponseEntity<Map<String, String>> cancelScan(@PathVariable String scanId) {
        boolean cancelled = scanHistoryService.cancelScan(scanId);
        if (cancelled) {
            return ResponseEntity.ok(Map.of("status", "cancelled", "scanId", scanId));
        } else {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of("status", "error", "message", "Scan not found or already completed"));
        }
    }

    @DeleteMapping("/{scanId}")
    public ResponseEntity<Map<String, String>> deleteScan(@PathVariable String scanId) {
        boolean deleted = scanHistoryService.deleteScan(scanId);
        if (deleted) {
            return ResponseEntity.ok(Map.of("status", "deleted", "scanId", scanId));
        } else {
            return ResponseEntity.notFound().build();
        }
    }
}

