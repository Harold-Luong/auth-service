package com.example.authservice.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Locale;
import java.time.Instant;
import java.util.UUID;

import com.example.authservice.config.JwtProperties;
import com.example.authservice.exception.GlobalException;
import com.example.authservice.exception.LoginThrottledException;
import com.example.authservice.request.LoginRequest;
import com.example.authservice.request.RefreshTokenRequest;
import com.example.authservice.request.RegisterRequest;
import com.example.authservice.response.LoginResponse;
import com.example.authservice.entity.User;
import com.example.authservice.enums.UserRole;
import com.example.authservice.repository.UserRepository;
import com.example.authservice.response.AccessTokenResponse;
import com.example.authservice.response.UserResponse;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final JwtProperties jwtProperties;
    private final RefreshSessionsService sessionsService;
    private final LoginThrottleService loginThrottleService;
    private final LoginAuditService loginAuditService;

    @Transactional
    public void register(RegisterRequest request) {
        String email = request.email().toLowerCase(Locale.ROOT).trim();
        if (userRepository.existsByEmail(email)) {
            throw new GlobalException("Email already exists", HttpStatus.BAD_REQUEST);
        }
        User user = new User();
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setActive(true);
        user.setRole(UserRole.USER);
        userRepository.save(user);
    }

    @Transactional
    public LoginResponse login(LoginRequest request, String clientIp) {
        String email = request.email().toLowerCase(Locale.ROOT).trim();
        try {
            loginThrottleService.acquire(email, clientIp);
        } catch (LoginThrottledException e) {
            loginAuditService.throttled(email, clientIp, e.getRetryAfterSeconds());
            throw e;
        }

        Optional<User> user = userRepository.findByEmail(email);
        if (user.isEmpty()) {
            loginAuditService.failed(email, clientIp, LoginAuditService.FailureReason.UNKNOWN_ACCOUNT);
            throw new GlobalException("Invalid email or password", HttpStatus.UNAUTHORIZED);
        }

        if (!user.get().isActive()) {
            loginAuditService.failed(email, clientIp, LoginAuditService.FailureReason.INACTIVE_ACCOUNT);
            throw new GlobalException("User is inactive", HttpStatus.FORBIDDEN);
        }

        boolean passwordMatched = passwordEncoder.matches(
                request.password(), user.get().getPasswordHash());

        if (!passwordMatched) {
            loginAuditService.failed(email, clientIp, LoginAuditService.FailureReason.INVALID_PASSWORD);
            throw new GlobalException("Invalid email or password", HttpStatus.UNAUTHORIZED);
        }

        String accessToken = jwtService.generateAccessToken(user.get());

        JwtService.RefreshTokenResult refreshTokenResult = jwtService.generateRefreshToken(user.get());

        Claims claims = jwtService.verifyRefreshToken(refreshTokenResult.getToken());

        try {
            sessionsService.createRefreshSession(
                    refreshTokenResult.getSessionId(),
                    user.get(),
                    hashToken(refreshTokenResult.getToken()),
                    claims.getExpiration().toInstant());
        } catch (Exception e) {
            throw new GlobalException("Failed to create refresh session", HttpStatus.INTERNAL_SERVER_ERROR);
        }

        String message = "Login successful";
        return new LoginResponse(
                message,
                new LoginResponse.Data(
                        jwtProperties.getType(),
                        accessToken,
                        refreshTokenResult.getToken(),
                        jwtProperties.getAccessTokenExpiration().toSeconds(),
                        jwtProperties.getRefreshTokenExpiration().toSeconds()));
    }

    @Transactional
    public AccessTokenResponse refresh(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new GlobalException("Refresh token is required", HttpStatus.BAD_REQUEST);
        }

        UUID sessionId;
        Long userId;
        try {
            Claims claims = jwtService.verifyRefreshToken(refreshToken);
            if (claims.getId() == null || claims.getSubject() == null
                    || claims.getExpiration() == null
                    || !claims.getExpiration().toInstant().isAfter(Instant.now())) {
                throw new IllegalArgumentException("Missing or expired refresh token claims");
            }
            sessionId = UUID.fromString(claims.getId());
            userId = Long.valueOf(claims.getSubject());
        } catch (JwtException | IllegalArgumentException e) {
            throw new GlobalException("Invalid refresh token", HttpStatus.UNAUTHORIZED);
        }

        User user = sessionsService.validateRefreshSession(sessionId, userId, hashToken(refreshToken));
        if (!user.isActive()) {
            throw new GlobalException("User is inactive", HttpStatus.FORBIDDEN);
        }
        sessionsService.revokeRefreshSession(sessionId);

        JwtService.RefreshTokenResult result = jwtService.generateRefreshToken(user);
        String newRefreshToken = result.getToken();
        Instant expiresAt = jwtService.verifyRefreshToken(newRefreshToken).getExpiration().toInstant();
        sessionsService.createRefreshSession(result.getSessionId(), user, hashToken(newRefreshToken), expiresAt);

        return new AccessTokenResponse(jwtService.generateAccessToken(user), newRefreshToken);
    }

    public UserResponse me(String id) {
        Optional<User> user = userRepository.findById(Long.parseLong(id));
        if (user.isEmpty()) {
            throw new GlobalException("User not found", HttpStatus.NOT_FOUND);
        }
        if (!user.get().isActive()) {
            throw new GlobalException("User is inactive", HttpStatus.FORBIDDEN);
        }
        return new UserResponse(user.get().getId(), user.get().getEmail(), user.get().isActive(),
                user.get().getRole().name());
    }

    @Transactional
    public void logout(RefreshTokenRequest request) {
        if (request.refreshToken() == null || request.refreshToken().isBlank()) {
            throw new GlobalException("Refresh token is required", HttpStatus.BAD_REQUEST);
        }
        UUID sessionId;
        Long userId;
        try {
            Claims claims = jwtService.verifyRefreshToken(request.refreshToken());
            if (claims.getId() == null || claims.getSubject() == null
                    || claims.getExpiration() == null
                    || !claims.getExpiration().toInstant().isAfter(Instant.now())) {
                throw new IllegalArgumentException("Missing or expired refresh token claims");
            }
            sessionId = UUID.fromString(claims.getId());
            userId = Long.valueOf(claims.getSubject());
        } catch (JwtException | IllegalArgumentException e) {
            throw new GlobalException("Invalid refresh token", HttpStatus.UNAUTHORIZED);
        }
        sessionsService.validateRefreshSession(sessionId, userId, hashToken(request.refreshToken()));
        sessionsService.revokeRefreshSession(sessionId);
    }

    @Transactional
    public void logoutAll(Authentication authentication) {
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new GlobalException("User is not authenticated", HttpStatus.UNAUTHORIZED);
        }
        String userIdStr = authentication.getName();
        Long userId;
        try {
            userId = Long.valueOf(userIdStr);
        } catch (NumberFormatException e) {
            throw new GlobalException("Invalid user ID in authentication", HttpStatus.UNAUTHORIZED);
        }
        sessionsService.revokeAllRefreshSessionsByUserId(userId);
    }

    public String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
