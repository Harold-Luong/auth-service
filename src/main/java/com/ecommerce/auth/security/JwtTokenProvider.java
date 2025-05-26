package com.ecommerce.auth.security;
import com.ecommerce.auth.config.JwtConfig;
import com.ecommerce.auth.entity.Role;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.security.Key;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtTokenProvider {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenProvider.class);

    private final JwtConfig jwtConfig;
    private final Clock clock;
    private Key signingKey;
    private JwtParser jwtParser;

    public JwtTokenProvider(JwtConfig jwtConfig) {
        if (jwtConfig == null) {
            throw new IllegalArgumentException("JwtConfig cannot be null");
        }
        if (jwtConfig.getExpiration() <= 0) {
            throw new IllegalArgumentException("Expiration time must be positive");
        }
        this.jwtConfig = jwtConfig;
        this.clock = Clock.systemUTC();
    }

    @PostConstruct
    private void init() {
        if (jwtConfig.getSecret() == null || jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalStateException("SECRET_KEY must be at least 32 bytes.");
        }
        this.signingKey = Keys.hmacShaKeyFor(jwtConfig.getSecret().getBytes(StandardCharsets.UTF_8));
        this.jwtParser = Jwts.parserBuilder().setSigningKey(this.signingKey).build();
        log.info("JWT SigningKey and Parser initialized");
    }

    /**
     * Generates a JWT access token for the specified username.
     *
     * @param userName the username to include in the token
     * @return the generated JWT token
     * @throws IllegalArgumentException if username is null or empty
     */
    public String generateAccessToken(String userName, Set<Role> roleSet) {

        if (userName == null || userName.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }

        long nowMillis = clock.millis();
        Date issuedAt = new Date(nowMillis);
        Date expiration = new Date(nowMillis + jwtConfig.getExpiration());

        // Convert roles to List<String>
        List<String> roleNames = roleSet.stream()
                .map(Role::name) // dùng name() thay vì toString()
                .toList();

        return Jwts.builder()
                .setSubject(userName)
                .claim("role", roleNames) // Thêm role vào đây
                .setIssuedAt(issuedAt)
                .setExpiration(expiration)
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Extracts the username from the JWT token.
     *
     * @param token the JWT token
     * @return the username
     * @throws IllegalArgumentException if token is invalid
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Extracts the JWT token from the Authorization header.
     *
     * @param bearerToken the Authorization header value
     * @return the JWT token or null if the header is invalid
     */
    public String extractTokenFromHeader(String bearerToken) {
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        if (!StringUtils.hasText(token)) {
            throw new IllegalArgumentException("Token cannot be null or empty");
        }
        try {
            final Claims claims = jwtParser.parseClaimsJws(token).getBody();
            return claimsResolver.apply(claims);
        } catch (ExpiredJwtException e) {
            log.warn("JWT token expired: {}", e.getMessage());
            throw new IllegalArgumentException("JWT token has expired", e);
        } catch (JwtException e) {
            log.warn("Invalid JWT token: {}", e.getMessage());
            throw new IllegalArgumentException("Invalid JWT token", e);
        }
    }

    /**
     * Checks if the token is valid for the given username.
     *
     * @param token    the JWT token
     * @param userName the username to validate against
     * @return true if the token is valid and not expired
     */
    public boolean isTokenValid(String token, String userName) {
        if (!StringUtils.hasText(token) || userName == null) {
            return false;
        }
        try {
            String extractedUserName = extractUsername(token);
            boolean isTokenExpired = extractClaim(token, Claims::getExpiration).before(new Date(clock.millis()));
            return extractedUserName.equals(userName) && !isTokenExpired;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
