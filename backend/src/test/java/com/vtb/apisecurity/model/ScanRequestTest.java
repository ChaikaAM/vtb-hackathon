package com.vtb.apisecurity.model;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class ScanRequestTest {

    private Validator validator;

    @BeforeEach
    void setUp() {
        ValidatorFactory factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @Test
    void validRequest_shouldPassValidation() {
        // given
        ScanRequest request = new ScanRequest();
        request.setOpenApiUrl("https://api.example.com/openapi.json");
        request.setApiBaseUrl("https://api.example.com");

        // when
        Set<ConstraintViolation<ScanRequest>> violations = validator.validate(request);

        // then
        assertThat(violations).isEmpty();
    }

    @Test
    void missingOpenApiUrl_shouldFailValidation() {
        // given
        ScanRequest request = new ScanRequest();
        request.setApiBaseUrl("https://api.example.com");
        // openApiUrl не установлен

        // when
        Set<ConstraintViolation<ScanRequest>> violations = validator.validate(request);

        // then
        assertThat(violations).hasSize(1);
        assertThat(violations.iterator().next().getMessage()).contains("OpenAPI URL is required");
    }

    @Test
    void missingApiBaseUrl_shouldFailValidation() {
        // given
        ScanRequest request = new ScanRequest();
        request.setOpenApiUrl("https://api.example.com/openapi.json");
        // apiBaseUrl не установлен

        // when
        Set<ConstraintViolation<ScanRequest>> violations = validator.validate(request);

        // then
        assertThat(violations).hasSize(1);
        assertThat(violations.iterator().next().getMessage()).contains("API Base URL is required");
    }

    @Test
    void emptyOpenApiUrl_shouldFailValidation() {
        // given
        ScanRequest request = new ScanRequest();
        request.setOpenApiUrl("");
        request.setApiBaseUrl("https://api.example.com");

        // when
        Set<ConstraintViolation<ScanRequest>> violations = validator.validate(request);

        // then
        assertThat(violations).isNotEmpty();
    }

    @Test
    void scanOptions_shouldHaveDefaultValues() {
        // given
        ScanRequest.ScanOptions options = new ScanRequest.ScanOptions();

        // then
        assertThat(options.isEnableStaticAnalysis()).isFalse();
        assertThat(options.isEnableDynamicTesting()).isFalse();
        assertThat(options.isEnableContractValidation()).isFalse();
        assertThat(options.isEnableAiAnalysis()).isTrue();
        assertThat(options.getTimeoutMs()).isEqualTo(300000);
        assertThat(options.getMaxConcurrentRequests()).isEqualTo(10);
    }

    @Test
    void scanOptions_shouldAllowCustomValues() {
        // given
        ScanRequest.ScanOptions options = new ScanRequest.ScanOptions();
        options.setEnableStaticAnalysis(true);
        options.setEnableDynamicTesting(true);
        options.setTimeoutMs(60000);
        options.setMaxConcurrentRequests(5);

        // then
        assertThat(options.isEnableStaticAnalysis()).isTrue();
        assertThat(options.isEnableDynamicTesting()).isTrue();
        assertThat(options.getTimeoutMs()).isEqualTo(60000);
        assertThat(options.getMaxConcurrentRequests()).isEqualTo(5);
    }
}
