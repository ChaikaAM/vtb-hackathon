package com.vtb.apisecurity.service.rate;

import lombok.extern.slf4j.Slf4j;
import okhttp3.Request;
import okhttp3.Response;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Сервис для управления rate limiting с поддержкой exponential backoff
 * и обработкой заголовка Retry-After
 */
@Slf4j
@Service
public class RateLimiterService {
    
    private final long baseDelayMs;
    private final long maxDelayMs;
    private final int maxRetries;
    private final double backoffMultiplier;
    
    // Token bucket для контроля rate limit
    private final AtomicLong lastRequestTime = new AtomicLong(0);
    private final ReentrantLock lock = new ReentrantLock();
    
    // Статистика для адаптации
    private final AtomicLong totalRequests = new AtomicLong(0);
    private final AtomicLong rateLimitHits = new AtomicLong(0);
    
    public RateLimiterService(
        @Value("${analysis.rate-limit-delay:100}") long baseDelayMs,
        @Value("${analysis.rate-limit-max-delay:10000}") long maxDelayMs,
        @Value("${analysis.rate-limit-max-retries:5}") int maxRetries,
        @Value("${analysis.rate-limit-backoff-multiplier:2.0}") double backoffMultiplier
    ) {
        this.baseDelayMs = baseDelayMs;
        this.maxDelayMs = maxDelayMs;
        this.maxRetries = maxRetries;
        this.backoffMultiplier = backoffMultiplier;
    }
    
    /**
     * Выполняет запрос с автоматической обработкой rate limiting
     * @param requestBuilder функция для создания запроса
     * @param executor функция для выполнения запроса
     * @return Response или null если все попытки исчерпаны
     */
    public Response executeWithRateLimit(
        Request request,
        RequestExecutor executor
    ) throws IOException {
        int attempt = 0;
        long delay = baseDelayMs;
        
        while (attempt <= maxRetries) {
            // Контроль базовой частоты запросов (только перед первой попыткой)
            if (attempt == 0) {
                waitForRateLimit();
            }
            
            try {
                Response response = executor.execute(request);
                totalRequests.incrementAndGet();
                
                // Проверяем на rate limit
                if (response.code() == 429) {
                    rateLimitHits.incrementAndGet();
                    log.warn("[RATE_LIMITER] Got 429 on attempt {}/{}, URL: {}", 
                        attempt + 1, maxRetries + 1, request.url());
                    
                    // Читаем Retry-After заголовок
                    String retryAfter = response.header("Retry-After");
                    long retryDelay = calculateRetryDelay(retryAfter, delay, attempt);
                    
                    response.close(); // Закрываем текущий response
                    
                    if (attempt < maxRetries) {
                        log.info("[RATE_LIMITER] Waiting {}ms before retry (Retry-After: {}, attempt: {})", 
                            retryDelay, retryAfter != null ? retryAfter : "not specified", attempt + 1);
                        
                        sleep(retryDelay);
                        
                        // Увеличиваем задержку для следующей попытки (exponential backoff)
                        delay = Math.min((long)(delay * backoffMultiplier), maxDelayMs);
                        attempt++;
                        continue;
                    } else {
                        log.error("[RATE_LIMITER] Max retries ({}) exceeded for URL: {}", 
                            maxRetries, request.url());
                        return null;
                    }
                }
                
                // Успешный ответ или другая ошибка (не 429)
                if (response.code() != 429) {
                    // Сбрасываем счетчик при успехе
                    if (attempt > 0) {
                        log.info("[RATE_LIMITER] Request succeeded after {} retries", attempt);
                    }
                    return response;
                }
                
            } catch (IOException e) {
                if (attempt < maxRetries) {
                    log.warn("[RATE_LIMITER] IO error on attempt {}/{}, retrying after {}ms: {}", 
                        attempt + 1, maxRetries + 1, delay, e.getMessage());
                    sleep(delay);
                    delay = Math.min((long)(delay * backoffMultiplier), maxDelayMs);
                    attempt++;
                } else {
                    log.error("[RATE_LIMITER] Max retries exceeded, throwing exception", e);
                    throw e;
                }
            }
        }
        
        return null;
    }
    
    /**
     * Вычисляет задержку для retry на основе Retry-After заголовка или exponential backoff
     */
    private long calculateRetryDelay(String retryAfterHeader, long currentDelay, int attempt) {
        if (retryAfterHeader != null && !retryAfterHeader.isEmpty()) {
            try {
                // Retry-After может быть в секундах или как HTTP date
                long retryAfterSeconds = Long.parseLong(retryAfterHeader);
                long retryDelay = TimeUnit.SECONDS.toMillis(retryAfterSeconds);
                
                // Минимальная задержка 1 секунда, даже если Retry-After меньше
                retryDelay = Math.max(retryDelay, 1000);
                
                // Добавляем небольшую случайную задержку для избежания thundering herd
                long jitter = (long)(retryDelay * 0.1 * Math.random());
                return retryDelay + jitter;
            } catch (NumberFormatException e) {
                log.debug("[RATE_LIMITER] Could not parse Retry-After header: {}", retryAfterHeader);
            }
        }
        
        // Используем exponential backoff с минимальной задержкой 1 секунда при 429
        // При первой попытке используем минимум 1 секунду
        if (attempt == 0) {
            return Math.max(currentDelay, 1000);
        }
        return Math.max(currentDelay, 1000);
    }
    
    /**
     * Контролирует базовую частоту запросов между вызовами
     */
    private void waitForRateLimit() {
        lock.lock();
        try {
            long now = System.currentTimeMillis();
            long lastRequest = lastRequestTime.get();
            long timeSinceLastRequest = now - lastRequest;
            
            if (timeSinceLastRequest < baseDelayMs) {
                long waitTime = baseDelayMs - timeSinceLastRequest;
                log.debug("[RATE_LIMITER] Waiting {}ms to respect rate limit", waitTime);
                sleep(waitTime);
            }
            
            lastRequestTime.set(System.currentTimeMillis());
        } finally {
            lock.unlock();
        }
    }
    
    private void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted during rate limit wait", e);
        }
    }
    
    /**
     * Получить статистику rate limiting
     */
    public RateLimitStats getStats() {
        return new RateLimitStats(
            totalRequests.get(),
            rateLimitHits.get(),
            totalRequests.get() > 0 ? (double) rateLimitHits.get() / totalRequests.get() : 0.0
        );
    }
    
    /**
     * Сброс статистики (для тестирования)
     */
    public void resetStats() {
        totalRequests.set(0);
        rateLimitHits.set(0);
    }
    
    /**
     * Функциональный интерфейс для выполнения запроса
     */
    @FunctionalInterface
    public interface RequestExecutor {
        Response execute(Request request) throws IOException;
    }
    
    /**
     * Статистика rate limiting
     */
    public static class RateLimitStats {
        private final long totalRequests;
        private final long rateLimitHits;
        private final double hitRate;
        
        public RateLimitStats(long totalRequests, long rateLimitHits, double hitRate) {
            this.totalRequests = totalRequests;
            this.rateLimitHits = rateLimitHits;
            this.hitRate = hitRate;
        }
        
        public long getTotalRequests() {
            return totalRequests;
        }
        
        public long getRateLimitHits() {
            return rateLimitHits;
        }
        
        public double getHitRate() {
            return hitRate;
        }
        
        @Override
        public String toString() {
            return String.format("RateLimitStats{total=%d, hits=%d, hitRate=%.2f%%}", 
                totalRequests, rateLimitHits, hitRate * 100);
        }
    }
}

