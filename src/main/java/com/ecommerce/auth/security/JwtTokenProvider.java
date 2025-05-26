package com.ecommerce.auth.security;

import com.ecommerce.auth.config.JwtConfig;
import com.ecommerce.auth.entity.Role;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import java.security.Key;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
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

    public String generateAccessToken(UUID userId, String userName, Set<Role> roleSet) {
        if (userName == null || userName.trim().isEmpty()) {
            throw new IllegalArgumentException("Username cannot be null or empty");
        }

        long nowMillis = clock.millis();
        Date issuedAt = new Date(nowMillis);
        Date expiration = new Date(nowMillis + jwtConfig.getExpiration());

        List<String> roleNames = roleSet.stream()
                .map(Role::name)
                .toList();

        return Jwts.builder()
                .setSubject(userName)
                .claim("userId", userId)
                .claim("roles", roleNames)
                .setIssuedAt(issuedAt)
                .setExpiration(expiration)
                .signWith(signingKey, SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date(clock.millis()));
    }

    public List<String> extractRoles(String token) {
        Object rolesObj = extractClaim(token, claims -> claims.get("roles"));
        if (rolesObj instanceof List<?>) {
            return ((List<?>) rolesObj).stream()
                    .map(Object::toString)
                    .collect(Collectors.toList());
        }
        return Collections.emptyList();
    }

    public String extractUserId(String token) {
        Object object = extractClaim(token, claims -> claims.get("userId"));
        return object.toString();
    }
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        Claims claims = jwtParser.parseClaimsJws(token).getBody();
        return claimsResolver.apply(claims);
    }

    public boolean validateToken(String token) {
        try {
            jwtParser.parseClaimsJws(token);
                return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String extractToken(ServerHttpRequest request) {
        String bearerToken = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
