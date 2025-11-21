package com.vtb.apisecurity.model.entity;

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
public class OperationRequest {
    private Map<String, ParameterInfo> pathParameters;
    private Map<String, ParameterInfo> queryParameters;
    private Map<String, ParameterInfo> headerParameters;
    private RequestBodyInfo requestBody;
}

