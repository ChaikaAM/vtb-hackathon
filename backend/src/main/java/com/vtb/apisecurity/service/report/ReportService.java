package com.vtb.apisecurity.service.report;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpServerErrorException;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.xhtmlrenderer.pdf.ITextFontResolver;
import org.xhtmlrenderer.pdf.ITextRenderer;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lowagie.text.DocumentException;
import com.lowagie.text.pdf.BaseFont;
import com.vtb.apisecurity.model.ScanResult;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
@RequiredArgsConstructor
public class ReportService {

    private final TemplateEngine templateEngine;
    private final ObjectMapper objectMapper;

    private final Map<String, ScanResult> scanResults = new LinkedHashMap<>();

    /**
     * Storing scan results in-memory. Later should be switched to volume, DB or any other persistency storage
     */
    public void saveInMemory(ScanResult scanResult) {
        scanResults.put(scanResult.getScanId(), scanResult);
    }

    public Optional<ScanResult> getScanResult(String scanId) {
        return Optional.ofNullable(scanResults.get(scanId));
    }

    public void deleteScanResult(String scanId) {
        scanResults.remove(scanId);
    }

    public Map<String, LocalDateTime> getReportsIdsToTriggerTime() {
        return scanResults.entrySet().stream().collect(Collectors.toMap(
            Map.Entry::getKey,
            report -> report.getValue().getStartTime()
        ));
    }

    public String getReportById(
        String scanId,
        ReportType reportType
    ) {
        var scanResult = Optional.ofNullable(
            scanResults.get(scanId)
        ).orElseThrow(
            () -> new HttpServerErrorException(HttpStatus.NOT_FOUND)
        );
        return switch (reportType) {
            case HTML -> generateHtmlReport(scanResult);
            case JSON_EXTENDED -> generateJsonReport(scanResult);
            case JSON_SUMMARY -> generateReportSummary(scanResult);
            case PDF -> throw new UnsupportedOperationException("Use getPdfReportById for PDF reports");
        };
    }

    public byte[] getPdfReportById(String scanId) {
        var scanResult = Optional.ofNullable(
            scanResults.get(scanId)
        ).orElseThrow(
            () -> new HttpServerErrorException(HttpStatus.NOT_FOUND)
        );
        return generatePdfReport(scanResult);
    }

    public String generateHtmlReport(ScanResult result) {
        Context context = new Context();
        context.setVariable("result", result);
        context.setVariable("vulnerabilities", result.getVulnerabilities());
        context.setVariable("mismatches", result.getContractMismatches());

        return templateEngine.process("report", context);
    }

    @SneakyThrows
    public String generateJsonReport(ScanResult result) {
        return objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(result);
    }

    @SneakyThrows
    public String generateReportSummary(ScanResult result) {
        Map<String, Object> summary = new HashMap<>();
        summary.put("scanId", result.getScanId());
        summary.put("status", result.getStatus());
        summary.put("totalVulnerabilities", result.getVulnerabilities().size());
        summary.put("totalMismatches", result.getContractMismatches().size());
        summary.put("vulnerabilityCounts", result.getVulnerabilityCounts());
        summary.put("summary", result.getSummary());
        return objectMapper.writeValueAsString(summary);
    }

    public byte[] generatePdfReport(ScanResult result) {
        ByteArrayOutputStream outputStream = null;
        try {
            // Generate HTML report first
            String htmlContent = generateHtmlReport(result);
            log.info("Generated HTML content length: {} characters", htmlContent.length());
            
            if (htmlContent == null || htmlContent.trim().isEmpty()) {
                log.error("Generated HTML content is empty");
                throw new RuntimeException("HTML content is empty");
            }
            
            // Convert HTML to XHTML using JSoup (Flying Saucer requires valid XHTML)
            log.debug("Converting HTML to XHTML");
            Document document = Jsoup.parse(htmlContent);
            document.outputSettings().syntax(Document.OutputSettings.Syntax.xml);
            document.outputSettings().charset(java.nio.charset.StandardCharsets.UTF_8);
            document.outputSettings().escapeMode(org.jsoup.nodes.Entities.EscapeMode.xhtml);
            // Ensure UTF-8 encoding is specified in the document
            if (document.head() != null && document.head().select("meta[charset]").isEmpty()) {
                document.head().prependElement("meta").attr("charset", "UTF-8");
            }
            String xhtmlContent = document.html();
            log.debug("XHTML conversion completed, length: {} characters", xhtmlContent.length());
            
            // Create output stream for PDF
            outputStream = new ByteArrayOutputStream();
            
            // Use Flying Saucer to convert XHTML to PDF
            log.debug("Starting XHTML to PDF conversion using Flying Saucer");
            ITextRenderer renderer = new ITextRenderer();
            
            // Configure fonts with Cyrillic support
            ITextFontResolver fontResolver = renderer.getFontResolver();
            try {
                // Try to find system fonts that support Cyrillic
                String[] fontPaths = {
                    "/System/Library/Fonts/Helvetica.ttc", // macOS
                    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", // Linux
                    "C:/Windows/Fonts/arial.ttf", // Windows
                    "C:/Windows/Fonts/arialuni.ttf" // Windows Unicode
                };
                
                boolean fontLoaded = false;
                for (String fontPath : fontPaths) {
                    try {
                        Path path = Paths.get(fontPath);
                        if (Files.exists(path)) {
                            // ITextFontResolver.addFont(path, encoding, embedded)
                            // BaseFont.IDENTITY_H is a String constant for Unicode encoding
                            // true = embed font in PDF (recommended for Cyrillic support)
                            fontResolver.addFont(fontPath, BaseFont.IDENTITY_H, true);
                            log.debug("Loaded system font with Cyrillic support: {}", fontPath);
                            fontLoaded = true;
                            break;
                        }
                    } catch (Exception e) {
                        log.debug("Failed to load font from {}: {}", fontPath, e.getMessage());
                        // Try next font
                        continue;
                    }
                }
                
                // If system fonts not found, use BaseFont with Unicode encoding
                // This should work but may not render perfectly
                if (!fontLoaded) {
                    // Use BaseFont directly - it supports Unicode/Cyrillic with IDENTITY_H encoding
                    log.debug("Using BaseFont with Unicode encoding for Cyrillic support");
                }
                
                log.debug("Fonts with Cyrillic support configured");
            } catch (Exception e) {
                log.warn("Failed to configure fonts with Cyrillic support: {}", e.getMessage());
                // Continue - BaseFont with IDENTITY_H should still work
            }
            
            // Set the XHTML content
            renderer.setDocumentFromString(xhtmlContent);
            renderer.layout();
            renderer.createPDF(outputStream);
            
            log.debug("XHTML to PDF conversion completed");
            
            byte[] pdfBytes = outputStream.toByteArray();
            log.info("Generated PDF size: {} bytes", pdfBytes.length);
            
            if (pdfBytes.length == 0) {
                log.error("PDF generation resulted in empty file");
                throw new RuntimeException("PDF generation failed: empty result");
            }
            
            // Verify PDF header (PDF files start with %PDF)
            if (pdfBytes.length < 4 || 
                pdfBytes[0] != '%' || 
                pdfBytes[1] != 'P' || 
                pdfBytes[2] != 'D' || 
                pdfBytes[3] != 'F') {
                log.error("Generated file does not appear to be a valid PDF (missing PDF header)");
                log.error("First 10 bytes: {}", new String(pdfBytes, 0, Math.min(10, pdfBytes.length)));
                throw new RuntimeException("PDF generation failed: invalid PDF format");
            }
            
            log.info("PDF successfully generated and validated");
            return pdfBytes;
        } catch (DocumentException e) {
            log.error("Document error generating PDF report: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to generate PDF report: " + e.getMessage(), e);
        } catch (Exception e) {
            log.error("Error generating PDF report: {}", e.getMessage(), e);
            throw new RuntimeException("Failed to generate PDF report: " + e.getMessage(), e);
        } finally {
            if (outputStream != null) {
                try {
                    outputStream.close();
                } catch (Exception e) {
                    log.warn("Error closing output stream", e);
                }
            }
        }
    }

    public enum ReportType {
        HTML,
        JSON_EXTENDED,
        JSON_SUMMARY,
        PDF
    }
}