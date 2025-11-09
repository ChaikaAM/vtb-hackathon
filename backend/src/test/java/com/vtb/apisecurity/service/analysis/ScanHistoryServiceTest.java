package com.vtb.apisecurity.service.analysis;

import com.vtb.apisecurity.model.ScanHistory;
import com.vtb.apisecurity.model.ScanRequest;
import com.vtb.apisecurity.model.ScanResult;
import com.vtb.apisecurity.service.report.ReportService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class ScanHistoryServiceTest {

    @Mock
    private ReportService reportService;

    private ScanHistoryService scanHistoryService;

    @BeforeEach
    void setUp() {
        scanHistoryService = new ScanHistoryService(reportService);
    }

    @Test
    void createHistory_shouldCreateNewHistoryEntry() {
        // given
        ScanRequest request = new ScanRequest();
        request.setOpenApiUrl("https://vbank.example.com/openapi.json");
        request.setApiBaseUrl("https://vbank.example.com/api");

        // when
        ScanHistory history = scanHistoryService.createHistory(request, "test-scan-id");

        // then
        assertThat(history).isNotNull();
        assertThat(history.getScanId()).isEqualTo("test-scan-id");
        assertThat(history.getBankName()).isEqualTo("VBank");
        assertThat(history.getStatus()).isEqualTo(ScanResult.ScanStatus.RUNNING);
        assertThat(history.getStartTime()).isNotNull();
    }

    @Test
    void createHistory_shouldExtractBankNameFromUrl() {
        // given
        ScanRequest abankRequest = new ScanRequest();
        abankRequest.setOpenApiUrl("https://abank.test.com/openapi.yaml");
        abankRequest.setApiBaseUrl("https://abank.test.com");

        // when
        ScanHistory history = scanHistoryService.createHistory(abankRequest, "abank-scan");

        // then
        assertThat(history.getBankName()).isEqualTo("ABank");
    }

    @Test
    void getHistory_shouldReturnHistoryIfExists() {
        // given
        ScanRequest request = new ScanRequest();
        request.setOpenApiUrl("https://test.com/openapi.json");
        request.setApiBaseUrl("https://test.com");

        scanHistoryService.createHistory(request, "existing-scan");

        // when
        Optional<ScanHistory> history = scanHistoryService.getHistory("existing-scan");

        // then
        assertThat(history).isPresent();
        assertThat(history.get().getScanId()).isEqualTo("existing-scan");
    }

    @Test
    void getHistory_shouldReturnEmptyIfNotFound() {
        // when
        Optional<ScanHistory> history = scanHistoryService.getHistory("non-existent");

        // then
        assertThat(history).isEmpty();
    }

    @Test
    void getAllHistory_shouldReturnAllScansSortedByTime() throws InterruptedException {
        // given
        ScanRequest request1 = new ScanRequest();
        request1.setOpenApiUrl("https://test1.com/openapi.json");
        request1.setApiBaseUrl("https://test1.com");

        ScanRequest request2 = new ScanRequest();
        request2.setOpenApiUrl("https://test2.com/openapi.json");
        request2.setApiBaseUrl("https://test2.com");

        scanHistoryService.createHistory(request1, "scan-1");
        Thread.sleep(10); // небольшая задержка чтобы время отличалось
        scanHistoryService.createHistory(request2, "scan-2");

        // when
        List<ScanHistory> allHistory = scanHistoryService.getAllHistory();

        // then
        assertThat(allHistory).hasSize(2);
        // должен быть отсортирован по времени в обратном порядке (новые первые)
        assertThat(allHistory.get(0).getScanId()).isEqualTo("scan-2");
        assertThat(allHistory.get(1).getScanId()).isEqualTo("scan-1");
    }

    @Test
    void updateHistory_shouldUpdateExistingHistory() {
        // given
        ScanRequest request = new ScanRequest();
        request.setOpenApiUrl("https://test.com/openapi.json");
        request.setApiBaseUrl("https://test.com");

        scanHistoryService.createHistory(request, "update-test");

        ScanResult result = ScanResult.builder()
                .scanId("update-test")
                .status(ScanResult.ScanStatus.COMPLETED)
                .build();
        result.setEndTime(java.time.LocalDateTime.now());
        result.setDurationMs(5000L);

        // when
        scanHistoryService.updateHistory("update-test", result);

        // then
        Optional<ScanHistory> updated = scanHistoryService.getHistory("update-test");
        assertThat(updated).isPresent();
        assertThat(updated.get().getStatus()).isEqualTo(ScanResult.ScanStatus.COMPLETED);
        assertThat(updated.get().getDurationMs()).isEqualTo(5000L);
    }

    @Test
    void deleteScan_shouldRemoveScanFromHistory() {
        // given
        ScanRequest request = new ScanRequest();
        request.setOpenApiUrl("https://test.com/openapi.json");
        request.setApiBaseUrl("https://test.com");

        scanHistoryService.createHistory(request, "delete-test");
        doNothing().when(reportService).deleteScanResult(anyString());

        // when
        boolean deleted = scanHistoryService.deleteScan("delete-test");

        // then
        assertThat(deleted).isTrue();
        assertThat(scanHistoryService.getHistory("delete-test")).isEmpty();
        verify(reportService).deleteScanResult("delete-test");
    }

    @Test
    void deleteScan_shouldReturnFalseIfNotExists() {
        // when
        boolean deleted = scanHistoryService.deleteScan("non-existent");

        // then
        assertThat(deleted).isFalse();
    }

    @Test
    void extractBankName_shouldHandleUnknownBank() {
        // given
        ScanRequest request = new ScanRequest();
        request.setOpenApiUrl("https://unknown-bank.com/openapi.json");
        request.setApiBaseUrl("https://unknown-bank.com");

        // when
        ScanHistory history = scanHistoryService.createHistory(request, "unknown-test");

        // then
        // метод извлекает имя из хоста URL, поэтому "unknown-bank.com" -> "Unknown-bank"
        assertThat(history.getBankName()).isEqualTo("Unknown-bank");
    }

    @Test
    void extractBankName_shouldReturnUnknownForNullUrl() {
        // given
        ScanRequest request = new ScanRequest();
        request.setOpenApiUrl(null);
        request.setApiBaseUrl("https://test.com");

        // when
        ScanHistory history = scanHistoryService.createHistory(request, "null-url-test");

        // then
        assertThat(history.getBankName()).isEqualTo("Unknown");
    }
}
