package com.vtb.apisecurity.service.rate;

import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@org.junit.jupiter.api.extension.ExtendWith(MockitoExtension.class)
class RateLimiterServiceTest {

    @Mock
    private Response response;

    @Mock
    private ResponseBody responseBody;

    private RateLimiterService rateLimiterService;
    private Request testRequest;

    @BeforeEach
    void setUp() {
        // используем маленькие задержки для тестов
        rateLimiterService = new RateLimiterService(10, 100, 3, 2.0);
        testRequest = new Request.Builder()
                .url("https://test.example.com/api")
                .build();
    }

    @Test
    void executeWithRateLimit_shouldReturnResponseOnSuccess() throws IOException {
        // given
        when(response.code()).thenReturn(200);
        RateLimiterService.RequestExecutor executor = mock(RateLimiterService.RequestExecutor.class);
        when(executor.execute(any(Request.class))).thenReturn(response);

        // when
        Response result = rateLimiterService.executeWithRateLimit(testRequest, executor);

        // then
        assertThat(result).isNotNull();
        assertThat(result.code()).isEqualTo(200);
        verify(executor, times(1)).execute(testRequest);
    }

    @Test
    void executeWithRateLimit_shouldRetryOn429() throws IOException {
        // given
        Response rateLimitResponse = mock(Response.class);
        Response successResponse = mock(Response.class);

        when(rateLimitResponse.code()).thenReturn(429);
        when(rateLimitResponse.header("Retry-After")).thenReturn(null);
        when(successResponse.code()).thenReturn(200);

        RateLimiterService.RequestExecutor executor = mock(RateLimiterService.RequestExecutor.class);
        when(executor.execute(testRequest))
                .thenReturn(rateLimitResponse)
                .thenReturn(successResponse);

        // when
        Response result = rateLimiterService.executeWithRateLimit(testRequest, executor);

        // then
        assertThat(result).isNotNull();
        assertThat(result.code()).isEqualTo(200);
        verify(executor, times(2)).execute(testRequest);
        verify(rateLimitResponse).close(); // должен закрыть response с 429
    }

    @Test
    void executeWithRateLimit_shouldRespectRetryAfterHeader() throws IOException {
        // given
        Response rateLimitResponse = mock(Response.class);
        Response successResponse = mock(Response.class);

        when(rateLimitResponse.code()).thenReturn(429);
        when(rateLimitResponse.header("Retry-After")).thenReturn("2"); // 2 секунды
        when(successResponse.code()).thenReturn(200);

        RateLimiterService.RequestExecutor executor = mock(RateLimiterService.RequestExecutor.class);
        when(executor.execute(testRequest))
                .thenReturn(rateLimitResponse)
                .thenReturn(successResponse);

        // when
        Response result = rateLimiterService.executeWithRateLimit(testRequest, executor);

        // then
        assertThat(result).isNotNull();
        assertThat(result.code()).isEqualTo(200);
        verify(executor, times(2)).execute(testRequest);
    }

    @Test
    void executeWithRateLimit_shouldReturnNullAfterMaxRetries() throws IOException {
        // given
        Response rateLimitResponse = mock(Response.class);
        when(rateLimitResponse.code()).thenReturn(429);
        when(rateLimitResponse.header("Retry-After")).thenReturn(null);

        RateLimiterService.RequestExecutor executor = mock(RateLimiterService.RequestExecutor.class);
        when(executor.execute(testRequest)).thenReturn(rateLimitResponse);

        // когда все попытки исчерпаны, сервис с maxRetries=3 сделает 4 попытки (0,1,2,3)
        // when
        Response result = rateLimiterService.executeWithRateLimit(testRequest, executor);

        // then
        assertThat(result).isNull();
        verify(executor, times(4)).execute(testRequest); // 1 начальная + 3 retry
    }

    @Test
    void executeWithRateLimit_shouldRetryOnIOException() throws IOException {
        // given
        Response successResponse = mock(Response.class);
        when(successResponse.code()).thenReturn(200);

        RateLimiterService.RequestExecutor executor = mock(RateLimiterService.RequestExecutor.class);
        when(executor.execute(testRequest))
                .thenThrow(new IOException("Network error"))
                .thenReturn(successResponse);

        // when
        Response result = rateLimiterService.executeWithRateLimit(testRequest, executor);

        // then
        assertThat(result).isNotNull();
        assertThat(result.code()).isEqualTo(200);
        verify(executor, times(2)).execute(testRequest);
    }

    @Test
    void getStats_shouldReturnCorrectStatistics() throws IOException {
        // given
        Response successResponse = mock(Response.class);
        Response rateLimitResponse = mock(Response.class);

        when(successResponse.code()).thenReturn(200);
        when(rateLimitResponse.code()).thenReturn(429);
        when(rateLimitResponse.header("Retry-After")).thenReturn(null);

        RateLimiterService.RequestExecutor executor = mock(RateLimiterService.RequestExecutor.class);
        when(executor.execute(testRequest))
                .thenReturn(successResponse)
                .thenReturn(rateLimitResponse)
                .thenReturn(successResponse);

        rateLimiterService.resetStats();

        // when
        rateLimiterService.executeWithRateLimit(testRequest, executor);
        rateLimiterService.executeWithRateLimit(testRequest, executor);

        RateLimiterService.RateLimitStats stats = rateLimiterService.getStats();

        // then
        assertThat(stats.getTotalRequests()).isGreaterThan(0);
        assertThat(stats.getRateLimitHits()).isGreaterThan(0);
        assertThat(stats.getHitRate()).isGreaterThan(0.0);
    }

    @Test
    void resetStats_shouldClearStatistics() throws IOException {
        // given
        Response response = mock(Response.class);
        when(response.code()).thenReturn(200);

        RateLimiterService.RequestExecutor executor = mock(RateLimiterService.RequestExecutor.class);
        when(executor.execute(testRequest)).thenReturn(response);

        rateLimiterService.executeWithRateLimit(testRequest, executor);

        // when
        rateLimiterService.resetStats();
        RateLimiterService.RateLimitStats stats = rateLimiterService.getStats();

        // then
        assertThat(stats.getTotalRequests()).isEqualTo(0);
        assertThat(stats.getRateLimitHits()).isEqualTo(0);
        assertThat(stats.getHitRate()).isEqualTo(0.0);
    }
}
