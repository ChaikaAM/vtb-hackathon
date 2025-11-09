package com.vtb.apisecurity.model;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class ScanResultTest {

    @Test
    void scanResultBuilder_shouldCreateResult() {
        // when
        ScanResult result = ScanResult.builder()
                .scanId("scan-123")
                .openApiUrl("https://api.example.com/openapi.json")
                .apiBaseUrl("https://api.example.com")
                .status(ScanResult.ScanStatus.RUNNING)
                .startTime(LocalDateTime.now())
                .build();

        // then
        assertThat(result.getScanId()).isEqualTo("scan-123");
        assertThat(result.getStatus()).isEqualTo(ScanResult.ScanStatus.RUNNING);
        assertThat(result.getStartTime()).isNotNull();
    }

    @Test
    void scanResult_shouldSupportAllStatuses() {
        // given
        ScanResult.ScanStatus[] statuses = ScanResult.ScanStatus.values();

        // then
        assertThat(statuses).containsExactly(
                ScanResult.ScanStatus.PENDING,
                ScanResult.ScanStatus.RUNNING,
                ScanResult.ScanStatus.COMPLETED,
                ScanResult.ScanStatus.FAILED,
                ScanResult.ScanStatus.CANCELLED
        );
    }

    @Test
    void scanResult_shouldCalculateDuration() {
        // given
        LocalDateTime start = LocalDateTime.now();
        LocalDateTime end = start.plusSeconds(5);

        // when
        ScanResult result = ScanResult.builder()
                .scanId("duration-test")
                .startTime(start)
                .endTime(end)
                .status(ScanResult.ScanStatus.COMPLETED)
                .build();

        result.setDurationMs(java.time.Duration.between(start, end).toMillis());

        // then
        assertThat(result.getDurationMs()).isEqualTo(5000L);
        assertThat(result.getStatus()).isEqualTo(ScanResult.ScanStatus.COMPLETED);
    }

    @Test
    void scanResult_shouldSupportVulnerabilityCounts() {
        // given
        Map<String, Integer> vulnCounts = new HashMap<>();
        vulnCounts.put("HIGH", 5);
        vulnCounts.put("MEDIUM", 3);
        vulnCounts.put("LOW", 2);

        // when
        ScanResult result = ScanResult.builder()
                .scanId("stats-test")
                .vulnerabilityCounts(vulnCounts)
                .totalEndpoints(10)
                .testedEndpoints(8)
                .build();

        // then
        assertThat(result.getVulnerabilityCounts()).hasSize(3);
        assertThat(result.getVulnerabilityCounts().get("HIGH")).isEqualTo(5);
        assertThat(result.getTotalEndpoints()).isEqualTo(10);
        assertThat(result.getTestedEndpoints()).isEqualTo(8);
    }

    @Test
    void scanResult_shouldSupportMetadata() {
        // given
        Map<String, Object> metadata = new HashMap<>();
        metadata.put("version", "1.0.0");
        metadata.put("analyzer", "API Security Analyzer");

        // when
        ScanResult result = ScanResult.builder()
                .scanId("metadata-test")
                .metadata(metadata)
                .build();

        // then
        assertThat(result.getMetadata()).isNotNull();
        assertThat(result.getMetadata().get("version")).isEqualTo("1.0.0");
    }

    @Test
    void scanResult_noArgsConstructor_shouldWork() {
        // when
        ScanResult result = new ScanResult();
        result.setScanId("test-id");
        result.setStatus(ScanResult.ScanStatus.PENDING);

        // then
        assertThat(result.getScanId()).isEqualTo("test-id");
        assertThat(result.getStatus()).isEqualTo(ScanResult.ScanStatus.PENDING);
    }
}
