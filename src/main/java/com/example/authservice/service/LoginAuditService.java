package com.example.authservice.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;

@Service
public class LoginAuditService {
    private static final Logger log = LoggerFactory.getLogger("auth.login.audit");

    public enum FailureReason {
        UNKNOWN_ACCOUNT, INVALID_PASSWORD, INACTIVE_ACCOUNT
    }

    public void failed(String email, String clientIp, FailureReason reason) {
        log.warn("event=login_failed accountHash={} ip={} reason={}", accountHash(email), safeIp(clientIp), reason);
    }

    public void throttled(String email, String clientIp, long retryAfterSeconds) {
        log.warn("event=login_throttled accountHash={} ip={} retryAfterSeconds={}",
                accountHash(email), safeIp(clientIp), retryAfterSeconds);
    }

    private String accountHash(String email) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(email.trim().toLowerCase(Locale.ROOT).getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e);
        }
    }

    private String safeIp(String clientIp) {
        return clientIp.replaceAll("[\\p{Cntrl}\\s]", "_");
    }
}
