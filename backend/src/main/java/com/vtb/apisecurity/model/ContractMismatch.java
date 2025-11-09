package com.vtb.apisecurity.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ContractMismatch {
    private String endpoint;
    private String method;
    private String type; // STATUS_CODE, SCHEMA, HEADER, MISSING_FIELD, EXTRA_FIELD
    private String field;
    private String expected;
    private String actual;
    private String message;
    private Vulnerability.Severity severity;
    private Map<String, Object> details;
}

