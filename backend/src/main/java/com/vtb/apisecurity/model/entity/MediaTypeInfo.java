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
public class MediaTypeInfo {
    private String mediaType;
    private SchemaInfo schema;
    private Object example;
    private Map<String, Object> examples;
}

