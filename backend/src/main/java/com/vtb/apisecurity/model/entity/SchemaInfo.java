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
public class SchemaInfo {
    private String type;
    private String format;
    private String description;
    private Object example;
    private Object defaultValue;
    private List<Object> enumValues;
    private Map<String, SchemaInfo> properties;
    private List<String> requiredFields;
    private SchemaInfo items; // для array
    private Integer minimum;
    private Integer maximum;
    private String pattern;
}

