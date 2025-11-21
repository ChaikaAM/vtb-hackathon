package com.vtb.apisecurity.model.entity;

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
public class EntityOperation {
    private String method;
    private String path;
    private String operationId;
    private String summary;
    private String description;
    private List<String> tags;
    private OperationRequest request;
    private List<Map<String, List<String>>> securityRequirements;
}

