package com.vtb.apisecurity.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class EndpointAnalysis {
    private String endpoint;
    private String method;
    private boolean requiresAuth;
    private boolean hasAuth;
    private List<String> securitySchemes;
    private List<Vulnerability> vulnerabilities;
    private List<ContractMismatch> mismatches;
    private Map<String, Object> metadata;
    private boolean tested;
}

