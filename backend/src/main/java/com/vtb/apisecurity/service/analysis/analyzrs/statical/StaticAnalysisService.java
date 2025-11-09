package com.vtb.apisecurity.service.analysis.analyzrs.statical;

import com.vtb.apisecurity.model.Vulnerability;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.Rule;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.impl.Api10UnsafeConsumptionRule;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.impl.Api1BrokenObjectLevelAuthRule;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.impl.Api2BrokenAuthenticationRule;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.impl.Api3BrokenPropertyLevelAuthRule;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.impl.Api4UnrestrictedResourceConsumptionRule;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.impl.Api5BrokenFunctionLevelAuthRule;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.impl.Api6UnrestrictedBusinessFlowRule;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.impl.Api7SsrfRule;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.impl.Api8SecurityMisconfigurationRule;
import com.vtb.apisecurity.service.analysis.analyzrs.statical.rules.impl.Api9ImproperInventoryRule;
import io.swagger.v3.oas.models.OpenAPI;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@Slf4j
public class StaticAnalysisService {
    
    private final List<Rule> rules;
    
    public StaticAnalysisService() {
        this.rules = new ArrayList<>();
        initializeRules();
    }
    
    private void initializeRules() {
        rules.add(new Api1BrokenObjectLevelAuthRule());
        rules.add(new Api2BrokenAuthenticationRule());
        rules.add(new Api3BrokenPropertyLevelAuthRule());
        rules.add(new Api4UnrestrictedResourceConsumptionRule());
        rules.add(new Api5BrokenFunctionLevelAuthRule());
        rules.add(new Api6UnrestrictedBusinessFlowRule());
        rules.add(new Api7SsrfRule());
        rules.add(new Api8SecurityMisconfigurationRule());
        rules.add(new Api9ImproperInventoryRule());
        rules.add(new Api10UnsafeConsumptionRule());
    }
    
    public List<Vulnerability> analyze(OpenAPI openAPI) {
        log.info("Starting static analysis");
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        
        for (Rule rule : rules) {
            try {
                List<Vulnerability> ruleVulnerabilities = rule.check(openAPI);
                vulnerabilities.addAll(ruleVulnerabilities);
                log.debug("Rule {} found {} vulnerabilities", rule.getClass().getSimpleName(), ruleVulnerabilities.size());
            } catch (Exception e) {
                log.error("Error executing rule {}: {}", rule.getClass().getSimpleName(), e.getMessage(), e);
            }
        }
        
        log.info("Static analysis completed. Found {} vulnerabilities", vulnerabilities.size());
        return vulnerabilities;
    }
}

