package com.example.authservice.service;

import com.example.authservice.config.JwtProperties;
import com.example.authservice.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtProperties jwtProperties;

    public SecretKey getAccessSecretKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtProperties.getAccessSecret()));
    }

    private SecretKey getRefreshSecretKey() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtProperties.getRefreshSecret()));
    }

    public String generateAccessToken(User user) {
        Instant now = Instant.now();
        Instant expirationAccess = now.plus(jwtProperties.getAccessTokenExpiration());

        return Jwts.builder()
                .subject(user.getId().toString())
                .claim("email", user.getEmail())
                .claim("role", user.getRole().toString())
                .issuer(jwtProperties.getAccessIssuer())
                .audience()
                .add(jwtProperties.getAccessAudience()).and()
                .issuedAt(Date.from(now))
                .expiration(Date.from(expirationAccess))
                .signWith(getAccessSecretKey())
                .compact();
    }

    public RefreshTokenResult generateRefreshToken(User user) {
        Instant now = Instant.now();
        Instant expiration = now.plus(jwtProperties.getRefreshTokenExpiration());
        UUID sessionId = UUID.randomUUID();
        String token = Jwts.builder()
                .subject(user.getId().toString())
                .claim("type", "refresh")
                .id(sessionId.toString())
                .issuer(jwtProperties.getRefreshIssuer())
                .audience()
                .add(jwtProperties.getRefreshAudience())
                .and()
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiration))
                .signWith(getRefreshSecretKey())
                .compact();

        return new RefreshTokenResult(token, sessionId);
    }

    public Claims verifyRefreshToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(getRefreshSecretKey())
                .requireIssuer(jwtProperties.getRefreshIssuer())
                .requireAudience(jwtProperties.getRefreshAudience())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        String type = claims.get("type", String.class);

        if (!"refresh".equals(type)) {
            throw new IllegalArgumentException(
                    "Invalid refresh token type");
        }
        return claims;
    }

    public boolean validateToken(String token) {
        try {
            parseToken(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public Claims parseToken(String token) {
        return Jwts.parser()
                .verifyWith(getAccessSecretKey())
                .requireIssuer(jwtProperties.getAccessIssuer())
                .requireAudience(jwtProperties.getAccessAudience())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    @Getter
    @AllArgsConstructor
    public static class RefreshTokenResult {
        private String token;
        private UUID sessionId;
    }
}
