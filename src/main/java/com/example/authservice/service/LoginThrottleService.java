package com.example.authservice.service;

import com.example.authservice.config.LoginThrottleProperties;
import com.example.authservice.exception.LoginThrottledException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/** Per-instance fixed windows. Reserve both budgets before password verification, including concurrent requests. */
@Service
@EnableConfigurationProperties(LoginThrottleProperties.class)
public class LoginThrottleService {
    private final int accountMaxAttempts;
    private final int ipMaxAttempts;
    private final int maxKeys;
    private final Duration window;
    private final Clock clock;
    private final Map<String, AttemptWindow> attempts = new LinkedHashMap<>();

    @Autowired
    public LoginThrottleService(LoginThrottleProperties properties) {
        this(properties, Clock.systemUTC());
    }

    LoginThrottleService(LoginThrottleProperties properties, Clock clock) {
        this.accountMaxAttempts = properties.getAccountMaxAttempts();
        this.ipMaxAttempts = properties.getIpMaxAttempts();
        this.maxKeys = properties.getMaxKeys();
        this.window = properties.getWindow();
        this.clock = clock;
    }

    public synchronized void acquire(String email, String clientIp) {
        Instant now = clock.instant();
        // All windows have the same duration and are inserted in creation order.
        var iterator = attempts.values().iterator();
        while (iterator.hasNext()) {
            if (iterator.next().expiresAt.isAfter(now)) {
                break;
            }
            iterator.remove();
        }

        String accountKey = "account:" + email.trim().toLowerCase(Locale.ROOT);
        String ipKey = "ip:" + clientIp;
        AttemptWindow account = attempts.get(accountKey);
        AttemptWindow ip = attempts.get(ipKey);
        long retryAfter = Math.max(retryAfter(account, accountMaxAttempts, now), retryAfter(ip, ipMaxAttempts, now));
        if (retryAfter > 0) {
            throw new LoginThrottledException(retryAfter);
        }

        int additionalKeys = (account == null ? 1 : 0) + (ip == null ? 1 : 0);
        if (attempts.size() + additionalKeys > maxKeys) {
            // Fail closed at capacity instead of letting key churn evict an active limit.
            throw new LoginThrottledException(secondsUntil(now, attempts.values().iterator().next().expiresAt));
        }

        attempts.computeIfAbsent(accountKey, key -> new AttemptWindow(now.plus(window))).count++;
        attempts.computeIfAbsent(ipKey, key -> new AttemptWindow(now.plus(window))).count++;
    }

    private long retryAfter(AttemptWindow entry, int limit, Instant now) {
        return entry != null && entry.count >= limit ? secondsUntil(now, entry.expiresAt) : 0;
    }

    private long secondsUntil(Instant now, Instant expiresAt) {
        return Math.max(1, (Duration.between(now, expiresAt).toMillis() + 999) / 1000);
    }

    private static class AttemptWindow {
        private final Instant expiresAt;
        private int count;

        private AttemptWindow(Instant expiresAt) {
            this.expiresAt = expiresAt;
        }
    }
}


