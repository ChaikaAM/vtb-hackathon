package com.vtb.apisecurity.service.analysis.analyzrs.statical.rules;

import com.vtb.apisecurity.model.Vulnerability;
import io.swagger.v3.oas.models.OpenAPI;
import org.springframework.core.Ordered;

import java.util.List;

public interface Rule extends Ordered {
    List<Vulnerability> check(OpenAPI openAPI);
    String getRuleId();
    String getDescription();
}

