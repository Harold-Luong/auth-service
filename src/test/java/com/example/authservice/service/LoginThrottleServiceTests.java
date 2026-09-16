package com.example.authservice.service;

import com.example.authservice.config.LoginThrottleProperties;
import com.example.authservice.exception.LoginThrottledException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class LoginThrottleServiceTests {
    private LoginThrottleProperties properties;
    private MutableClock clock;

    @BeforeEach
    void setUp() {
        properties = new LoginThrottleProperties();
        properties.setAccountMaxAttempts(2);
        properties.setIpMaxAttempts(3);
        properties.setWindow(Duration.ofSeconds(60));
        clock = new MutableClock();
    }

    @Test
    void normalizesAccountAndBlocksAcrossIps() {
        var throttle = new LoginThrottleService(properties, clock);
        throttle.acquire("USER@example.com", "192.0.2.1");
        throttle.acquire(" user@example.com ", "192.0.2.2");
        assertEquals(60, assertThrows(LoginThrottledException.class,
                () -> throttle.acquire("user@example.com", "192.0.2.3")).getRetryAfterSeconds());
        assertDoesNotThrow(() -> throttle.acquire("other@example.com", "192.0.2.3"));
    }

    @Test
    void blocksIpAcrossAccounts() {
        var throttle = new LoginThrottleService(properties, clock);
        for (int i = 0; i < 3; i++) {
            throttle.acquire("user" + i + "@example.com", "192.0.2.1");
        }
        assertThrows(LoginThrottledException.class,
                () -> throttle.acquire("new@example.com", "192.0.2.1"));
        assertDoesNotThrow(() -> throttle.acquire("new@example.com", "192.0.2.2"));
    }

    @Test
    void expiresAtBoundaryAndRejectedRequestsDoNotExtendWindow() {
        var throttle = new LoginThrottleService(properties, clock);
        throttle.acquire("user@example.com", "192.0.2.1");
        throttle.acquire("user@example.com", "192.0.2.1");
        clock.advance(Duration.ofMillis(59500));
        assertEquals(1, assertThrows(LoginThrottledException.class,
                () -> throttle.acquire("user@example.com", "192.0.2.1")).getRetryAfterSeconds());
        clock.advance(Duration.ofMillis(500));
        assertDoesNotThrow(() -> throttle.acquire("user@example.com", "192.0.2.1"));
    }

    @Test
    void rejectedAccountDoesNotConsumeUnrelatedIpBudget() {
        var throttle = new LoginThrottleService(properties, clock);
        throttle.acquire("user@example.com", "192.0.2.1");
        throttle.acquire("user@example.com", "192.0.2.1");
        for (int i = 0; i < 5; i++) {
            assertThrows(LoginThrottledException.class,
                    () -> throttle.acquire("user@example.com", "192.0.2.2"));
        }
        for (int i = 0; i < 3; i++) {
            throttle.acquire("other" + i + "@example.com", "192.0.2.2");
        }
    }

    @Test
    void retryAfterUsesLaterOfBothLimits() {
        properties.setIpMaxAttempts(2);
        var throttle = new LoginThrottleService(properties, clock);
        throttle.acquire("user@example.com", "192.0.2.1");
        clock.advance(Duration.ofSeconds(10));
        throttle.acquire("other@example.com", "192.0.2.2");
        throttle.acquire("user@example.com", "192.0.2.2");
        assertEquals(60, assertThrows(LoginThrottledException.class,
                () -> throttle.acquire("user@example.com", "192.0.2.2")).getRetryAfterSeconds());
    }

    @Test
    void capacityRejectsNewKeysWithoutEvictingActiveLimitsAndRecoversAfterExpiry() {
        properties.setMaxKeys(2);
        var throttle = new LoginThrottleService(properties, clock);
        throttle.acquire("user@example.com", "192.0.2.1");
        assertThrows(LoginThrottledException.class,
                () -> throttle.acquire("other@example.com", "192.0.2.2"));
        throttle.acquire("user@example.com", "192.0.2.1");
        assertThrows(LoginThrottledException.class,
                () -> throttle.acquire("user@example.com", "192.0.2.1"));
        clock.advance(Duration.ofSeconds(60));
        assertDoesNotThrow(() -> throttle.acquire("other@example.com", "192.0.2.2"));
    }

    @Test
    void concurrentRequestsCannotOverrunAccountBudget() throws Exception {
        properties.setAccountMaxAttempts(10);
        properties.setIpMaxAttempts(100);
        var throttle = new LoginThrottleService(properties, clock);
        try (var pool = Executors.newFixedThreadPool(12)) {
            var ready = new CountDownLatch(12);
            var start = new CountDownLatch(1);
            var results = new ArrayList<Future<Boolean>>();
            for (int i = 0; i < 100; i++) {
                results.add(pool.submit(() -> {
                    ready.countDown();
                    assertTrue(start.await(5, TimeUnit.SECONDS));
                    try {
                        throttle.acquire("user@example.com", "192.0.2.1");
                        return true;
                    } catch (LoginThrottledException e) {
                        return false;
                    }
                }));
            }
            try {
                assertTrue(ready.await(5, TimeUnit.SECONDS));
            } finally {
                start.countDown();
            }
            int admitted = 0;
            for (var result : results) {
                if (result.get(5, TimeUnit.SECONDS)) {
                    admitted++;
                }
            }
            assertEquals(10, admitted);
        }
    }

    private static class MutableClock extends Clock {
        private Instant now = Instant.parse("2026-01-01T00:00:00Z");

        void advance(Duration duration) { now = now.plus(duration); }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
}
