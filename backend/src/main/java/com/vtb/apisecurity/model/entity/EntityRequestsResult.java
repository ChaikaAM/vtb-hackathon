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
public class EntityRequestsResult {
    private String entityName;
    private Integer operationsCount;
    private List<GeneratedRequest> requests;
    private String summary;
    private Map<String, List<GeneratedRequest>> groupedByType; // CREATE, READ, UPDATE, DELETE
}

