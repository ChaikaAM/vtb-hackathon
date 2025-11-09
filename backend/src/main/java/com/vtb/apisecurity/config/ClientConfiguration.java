package com.vtb.apisecurity.config;

import okhttp3.OkHttpClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
public class ClientConfiguration {

    @Bean
    public OkHttpClient bankingApiHttpClient(
        @Value("${analysis.timeout:300000}") int timeoutMs
    ) {
        return new OkHttpClient.Builder()
            .connectTimeout(timeoutMs, TimeUnit.MILLISECONDS)
            .readTimeout(timeoutMs, TimeUnit.MILLISECONDS)
            .build();
    }

    @Bean
    public OkHttpClient aiAgentClient(
        @Value("${yandexgpt.timeout:30000}") int timeoutMs
    ) {
        return new OkHttpClient.Builder()
            .connectTimeout(timeoutMs, TimeUnit.MILLISECONDS)
            .readTimeout(timeoutMs, TimeUnit.MILLISECONDS)
            .build();
    }
}
