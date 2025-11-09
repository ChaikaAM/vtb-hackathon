package com.vtb.apisecurity.controller;

import com.vtb.apisecurity.model.ScanRequest;
import com.vtb.apisecurity.model.ScanResult;
import com.vtb.apisecurity.service.analysis.AnalysisService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AnalysisControllerTest {

    @Mock
    private AnalysisService analysisService;

    @InjectMocks
    private AnalysisController controller;

    @Test
    void healthCheck_shouldReturnUp() {
        // когда
        ResponseEntity<Map<String, String>> response = controller.health();

        // тогда
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().get("status")).isEqualTo("UP");
    }

    @Test
    void startScan_shouldReturnScanResult() {
        // given
        ScanRequest request = new ScanRequest();
        request.setOpenApiUrl("https://api.example.com/openapi.json");
        request.setApiBaseUrl("https://api.example.com");

        ScanResult expectedResult = ScanResult.builder()
                .scanId("test-scan-id")
                .status(ScanResult.ScanStatus.RUNNING)
                .build();

        when(analysisService.startAnalysis(any(ScanRequest.class))).thenReturn(expectedResult);

        // when
        ScanResult result = controller.startScan(request);

        // then
        assertThat(result).isNotNull();
        assertThat(result.getScanId()).isEqualTo("test-scan-id");
        assertThat(result.getStatus()).isEqualTo(ScanResult.ScanStatus.RUNNING);
    }

    @Test
    void startScan_shouldPassRequestToService() {
        // given
        ScanRequest request = new ScanRequest();
        request.setOpenApiUrl("https://test.com/openapi.yaml");
        request.setApiBaseUrl("https://test.com");

        ScanResult scanResult = ScanResult.builder()
                .scanId("scan-123")
                .status(ScanResult.ScanStatus.RUNNING)
                .build();

        when(analysisService.startAnalysis(request)).thenReturn(scanResult);

        // when
        ScanResult result = controller.startScan(request);

        // then
        assertThat(result.getScanId()).isEqualTo("scan-123");
    }
}
