package com.vtb.apisecurity.controller;

import com.vtb.apisecurity.service.report.ReportService;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.Map;

@RestController
@RequestMapping("/reports")
@Slf4j
@AllArgsConstructor
public class ReportController {

    private final ReportService reportService;

    /**
     *
     * @return startTime by reportId
     */
    @GetMapping
    public Map<String, LocalDateTime> getReport() {
        return reportService.getReportsIdsToTriggerTime();
    }

    /**
     * On UI use JSON reportType to render
     */
    @GetMapping("/{scanId}/{reportType}")
    public ResponseEntity<?> getReport(
        @PathVariable String scanId,
        @PathVariable ReportService.ReportType reportType
    ) {
        HttpHeaders headers = new HttpHeaders();
        
        switch (reportType) {
            case HTML: {
                String content = reportService.getReportById(scanId, reportType);
                headers.setContentType(MediaType.TEXT_HTML);
                headers.setContentDispositionFormData("attachment", "report-" + scanId + ".html");
                return ResponseEntity.ok()
                        .headers(headers)
                        .body(content);
            }
            case JSON_EXTENDED:
            case JSON_SUMMARY: {
                String content = reportService.getReportById(scanId, reportType);
                headers.setContentType(MediaType.APPLICATION_JSON);
                headers.setContentDispositionFormData("attachment", "report-" + scanId + ".json");
                return ResponseEntity.ok()
                        .headers(headers)
                        .body(content);
            }
            case PDF: {
                byte[] pdfContent = reportService.getPdfReportById(scanId);
                headers.setContentType(MediaType.APPLICATION_PDF);
                headers.setContentLength(pdfContent.length);
                headers.setContentDispositionFormData("attachment", "report-" + scanId + ".pdf");
                headers.set("Cache-Control", "no-cache, no-store, must-revalidate");
                headers.set("Pragma", "no-cache");
                headers.set("Expires", "0");
                return ResponseEntity.ok()
                        .headers(headers)
                        .body(pdfContent);
            }
            default:
                return ResponseEntity.badRequest().build();
        }
    }
}

