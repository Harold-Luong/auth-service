package com.example.authservice.service;

import com.example.authservice.entity.RefreshSessions;
import com.example.authservice.entity.User;
import com.example.authservice.exception.GlobalException;
import com.example.authservice.repository.RefreshSessionsRepository;

import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Service
@AllArgsConstructor
public class RefreshSessionsService {

    private final RefreshSessionsRepository refreshSessionsRepository;

    @Transactional(Transactional.TxType.MANDATORY)
    public User validateRefreshSession(UUID sessionId, Long userId, String tokenHash) {
        // Keep the row locked through validation, revocation and replacement in the caller's transaction.
        RefreshSessions session = refreshSessionsRepository.findByIdForUpdate(sessionId)
                .orElseThrow(() -> new GlobalException("Invalid refresh token", HttpStatus.UNAUTHORIZED));
        if (session.getRevokedAt() != null
                || session.getExpiresAt() == null || !session.getExpiresAt().isAfter(Instant.now())
                || !tokenHash.equals(session.getTokenHash())
                || session.getUser() == null || !userId.equals(session.getUser().getId())) {
            throw new GlobalException("Invalid refresh token", HttpStatus.UNAUTHORIZED);
        }
        return session.getUser();
    }

    public void createRefreshSession(UUID id, User user, String tokenHash, Instant expiresAt) {
        RefreshSessions session = new RefreshSessions();
        session.setUuid(id);
        session.setUser(user);
        session.setTokenHash(tokenHash);
        session.setExpiresAt(expiresAt);
        session.setCreatedAt(Instant.now());
        refreshSessionsRepository.save(session);
    }

    @Transactional
    public void revokeRefreshSession(UUID sessionId) {
        RefreshSessions session = refreshSessionsRepository.findById(sessionId)
                .orElseThrow(() -> new GlobalException("Session not found", HttpStatus.NOT_FOUND));
        session.setRevokedAt(Instant.now());
    }

    @Transactional
    public void revokeAllRefreshSessionsByUserId(Long userId) {
        refreshSessionsRepository.findAll().stream()
                .filter(session -> session.getUser() != null && userId.equals(session.getUser().getId()))
                .forEach(session -> {
                    if (session.getRevokedAt() == null) {
                        session.setRevokedAt(Instant.now());
                    }
                });
    }
}
