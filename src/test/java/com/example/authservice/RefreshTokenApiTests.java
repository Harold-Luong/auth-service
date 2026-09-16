package com.example.authservice;

import com.example.authservice.config.JwtProperties;
import com.example.authservice.entity.RefreshSessions;
import com.example.authservice.entity.User;
import com.example.authservice.enums.UserRole;
import com.example.authservice.exception.GlobalException;
import com.example.authservice.response.AccessTokenResponse;
import com.example.authservice.repository.RefreshSessionsRepository;
import com.example.authservice.repository.UserRepository;
import com.example.authservice.service.AuthService;
import com.example.authservice.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.UUID;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "spring.datasource.url=jdbc:h2:mem:refresh_rotation_test;DB_CLOSE_DELAY=-1;LOCK_TIMEOUT=10000")
@AutoConfigureMockMvc
class RefreshTokenApiTests {
    @Autowired
    private MockMvc mvc;
    @Autowired
    private ObjectMapper mapper;
    @Autowired
    private UserRepository users;
    @Autowired
    private RefreshSessionsRepository sessions;
    @MockitoSpyBean
    private JwtService jwtService;
    @Autowired
    private AuthService authService;
    @Autowired
    private JwtProperties properties;
    @Autowired
    private PasswordEncoder passwordEncoder;

    private User user;
    private RefreshSessions session;
    private String refreshToken;

    @BeforeEach
    void setUp() {
        sessions.deleteAll();
        users.deleteAll();
        user = new User();
        user.setEmail("refresh@example.com");
        user.setPasswordHash(passwordEncoder.encode("password123"));
        user.setActive(true);
        user.setRole(UserRole.USER);
        user = users.saveAndFlush(user);

        JwtService.RefreshTokenResult result = jwtService.generateRefreshToken(user);
        refreshToken = result.getToken();
        session = new RefreshSessions();
        session.setUuid(result.getSessionId());
        session.setUser(user);
        session.setTokenHash(authService.hashToken(refreshToken));
        session.setExpiresAt(jwtService.verifyRefreshToken(refreshToken).getExpiration().toInstant());
        session.setCreatedAt(Instant.now());
        session = sessions.saveAndFlush(session);
    }

    @Test
    void loginRefreshAndAccessProtectedEndpoint() throws Exception {
        String login = mvc.perform(post("/api/v1/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of(
                        "email", user.getEmail(), "password", "password123"))))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        String token = mapper.readTree(login).path("data").path("refreshToken").asText();
        String response = mvc.perform(post("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON).content(body(token)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andReturn().getResponse().getContentAsString();
        String accessToken = mapper.readTree(response).path("accessToken").asText();
        Claims claims = jwtService.parseToken(accessToken);
        assertEquals(user.getId().toString(), claims.getSubject());
        assertEquals(user.getEmail(), claims.get("email", String.class));
        assertNotNull(claims.getExpiration());
        mvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk()).andExpect(jsonPath("$.email").value(user.getEmail()));

        assertUnauthorized(token);
        String replacement = mapper.readTree(response).path("refreshToken").asText();
        assertNotEquals(token, replacement);
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(body(replacement)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.refeshToken").doesNotExist());
    }

    @Test
    void storesExactlyTheReturnedTokenAndRevokesOldSession() throws Exception {
        AccessTokenResponse response = authService.refresh(refreshToken);
        Claims claims = jwtService.verifyRefreshToken(response.refreshToken());
        RefreshSessions replacement = sessions.findById(UUID.fromString(claims.getId())).orElseThrow();

        assertNotEquals(session.getUuid(), replacement.getUuid());
        assertEquals(authService.hashToken(response.refreshToken()), replacement.getTokenHash());
        assertNotEquals(response.refreshToken(), replacement.getTokenHash());
        assertEquals(claims.getExpiration().toInstant(), replacement.getExpiresAt());
        assertNull(replacement.getRevokedAt());
        assertNotNull(sessions.findById(session.getUuid()).orElseThrow().getRevokedAt());
        assertEquals(2, sessions.count());
        assertUnauthorized(refreshToken);

        mvc.perform(post("/api/v1/auth/logout").contentType(MediaType.APPLICATION_JSON)
                        .content(body(response.refreshToken())))
                .andExpect(status().isOk());
        assertUnauthorized(response.refreshToken());
    }

    @Test
    void failedRotationRollsBackRevocationAndReplacement() {
        doThrow(new IllegalStateException("Signing unavailable")).when(jwtService).generateAccessToken(any(User.class));

        assertThrows(IllegalStateException.class, () -> authService.refresh(refreshToken));

        assertEquals(1, sessions.count());
        assertNull(sessions.findById(session.getUuid()).orElseThrow().getRevokedAt());
        reset(jwtService);
        assertNotNull(authService.refresh(refreshToken).refreshToken());
    }

    @Test
    void concurrentRefreshCanConsumeTheOldTokenOnlyOnce() throws Exception {
        CountDownLatch firstValidated = new CountDownLatch(1);
        CountDownLatch releaseFirst = new CountDownLatch(1);
        CountDownLatch secondStarted = new CountDownLatch(1);
        doAnswer(invocation -> {
            firstValidated.countDown();
            assertTrue(releaseFirst.await(5, TimeUnit.SECONDS));
            return invocation.callRealMethod();
        }).when(jwtService).generateRefreshToken(any(User.class));

        try (var executor = Executors.newFixedThreadPool(2)) {
            var first = executor.submit(() -> refreshStatus(refreshToken));
            try {
                assertTrue(firstValidated.await(5, TimeUnit.SECONDS));
                var second = executor.submit(() -> {
                    secondStarted.countDown();
                    return refreshStatus(refreshToken);
                });
                assertTrue(secondStarted.await(5, TimeUnit.SECONDS));
                releaseFirst.countDown();
                assertEquals(List.of(200, 401), List.of(
                        first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS)));
            } finally {
                releaseFirst.countDown();
            }
        }
        assertEquals(2, sessions.count());
        assertEquals(1, sessions.findAll().stream().filter(s -> s.getRevokedAt() == null).count());
    }

    private int refreshStatus(String token) {
        try {
            authService.refresh(token);
            return 200;
        } catch (GlobalException e) {
            assertEquals(HttpStatus.UNAUTHORIZED, e.getStatus());
            return e.getStatus().value();
        }
    }

    @Test
    void refreshWorksWithExpiredAccessTokenHeader() throws Exception {
        String expiredAccess = Jwts.builder().subject(user.getId().toString())
                .issuer(properties.getAccessIssuer()).audience().add(properties.getAccessAudience()).and()
                .expiration(Date.from(Instant.now().minusSeconds(60)))
                .signWith(jwtService.getAccessSecretKey()).compact();
        mvc.perform(post("/api/v1/auth/refresh").header("Authorization", "Bearer " + expiredAccess)
                .contentType(MediaType.APPLICATION_JSON).content(body(refreshToken)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.accessToken").isNotEmpty());
        mvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + expiredAccess))
                .andExpect(status().isUnauthorized());
    }

    @ParameterizedTest
    @ValueSource(strings = { "{}", "{\"refreshToken\":null}", "{\"refreshToken\":\"\"}",
            "{\"refreshToken\":\"   \"}", "null", "{", "" })
    void rejectsMissingOrMalformedRequest(String body) throws Exception {
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isBadRequest());
    }

    @ParameterizedTest
    @ValueSource(strings = { "missing", "revoked", "expired", "wrong-hash", "wrong-user" })
    void rejectsInvalidSession(String scenario) throws Exception {
        switch (scenario) {
            case "missing" -> sessions.deleteAll();
            case "revoked" -> session.setRevokedAt(Instant.now());
            case "expired" -> session.setExpiresAt(Instant.now().minusSeconds(60));
            case "wrong-hash" -> session.setTokenHash("0".repeat(64));
            case "wrong-user" -> {
                User other = new User();
                other.setEmail("other@example.com");
                other.setPasswordHash(user.getPasswordHash());
                other.setActive(true);
                other.setRole(UserRole.USER);
                session.setUser(users.saveAndFlush(other));
            }
        }
        if (!"missing".equals(scenario)) {
            sessions.saveAndFlush(session);
        }
        assertUnauthorized(refreshToken);
    }

    @Test
    void rejectsInactiveUser() throws Exception {
        user.setActive(false);
        users.saveAndFlush(user);
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(body(refreshToken)))
                .andExpect(status().isForbidden()).andExpect(jsonPath("$.message").value("User is inactive"));
    }

    @ParameterizedTest
    @ValueSource(strings = { "malformed", "access-token", "signature", "expired", "issuer", "audience",
            "type", "missing-expiration", "missing-id", "invalid-id", "missing-subject", "invalid-subject" })
    void rejectsInvalidJwt(String scenario) throws Exception {
        JwtBuilder builder = Jwts.builder().subject(user.getId().toString()).id(session.getUuid().toString())
                .claim("type", "refresh").issuer(properties.getRefreshIssuer())
                .audience().add(properties.getRefreshAudience()).and()
                .expiration(Date.from(Instant.now().plusSeconds(600)));
        switch (scenario) {
            case "expired" -> builder.expiration(Date.from(Instant.now().minusSeconds(60)));
            case "issuer" -> builder.issuer("other-service");
            case "audience" -> builder.audience().clear().add("other-api").and();
            case "type" -> builder.claim("type", "access");
            case "missing-expiration" -> builder.expiration(null);
            case "missing-id" -> builder.id(null);
            case "invalid-id" -> builder.id("not-a-uuid");
            case "missing-subject" -> builder.subject(null);
            case "invalid-subject" -> builder.subject("not-a-user-id");
        }
        String token = switch (scenario) {
            case "malformed" -> "not-a-jwt";
            case "access-token" -> jwtService.generateAccessToken(user);
            case "signature" -> builder.signWith(jwtService.getAccessSecretKey()).compact();
            default -> builder.signWith(Keys.hmacShaKeyFor(Decoders.BASE64.decode(properties.getRefreshSecret())))
                    .compact();
        };
        // Match the stored hash so a bad JWT cannot pass just because its session
        // exists.
        session.setTokenHash(authService.hashToken(token));
        sessions.saveAndFlush(session);
        assertUnauthorized(token);
    }

    private String body(String token) {
        return mapper.writeValueAsString(Map.of("refreshToken", token));
    }

    private void assertUnauthorized(String token) throws Exception {
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON).content(body(token)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("401"))
                .andExpect(jsonPath("$.message").value("Invalid refresh token"));
    }
}
