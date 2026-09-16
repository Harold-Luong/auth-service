package com.example.authservice;

import com.example.authservice.config.JwtProperties;
import com.example.authservice.entity.User;
import com.example.authservice.enums.UserRole;
import com.example.authservice.repository.RefreshSessionsRepository;
import com.example.authservice.repository.UserRepository;
import com.example.authservice.service.AuthService;
import com.example.authservice.service.JwtService;
import com.example.authservice.service.RefreshSessionsService;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class LogoutAllApiTests {
    @Autowired private MockMvc mvc;
    @Autowired private UserRepository users;
    @Autowired private RefreshSessionsRepository sessions;
    @Autowired private RefreshSessionsService sessionsService;
    @Autowired private AuthService authService;
    @Autowired private JwtService jwtService;
    @Autowired private JwtProperties properties;

    private User user;
    private JwtService.RefreshTokenResult firstSession;
    private JwtService.RefreshTokenResult secondSession;
    private JwtService.RefreshTokenResult otherUserSession;

    @BeforeEach
    void setUp() {
        sessions.deleteAll();
        users.deleteAll();
        user = createUser("logout@example.com");
        firstSession = createSession(user);
        secondSession = createSession(user);
        otherUserSession = createSession(createUser("other@example.com"));
    }

    @Test
    void revokesOnlyAuthenticatedUsersSessionsAndAllowsRetry() throws Exception {
        String accessToken = jwtService.generateAccessToken(user);
        mvc.perform(post("/api/v1/auth/logout-all").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("All sessions logged out successfully"));

        assertNotNull(sessions.findById(firstSession.getSessionId()).orElseThrow().getRevokedAt());
        assertNotNull(sessions.findById(secondSession.getSessionId()).orElseThrow().getRevokedAt());
        assertNull(sessions.findById(otherUserSession.getSessionId()).orElseThrow().getRevokedAt());
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content(body(firstSession.getToken())))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content(body(secondSession.getToken())))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/auth/refresh").contentType(MediaType.APPLICATION_JSON)
                        .content(body(otherUserSession.getToken())))
                .andExpect(status().isOk());
        mvc.perform(post("/api/v1/auth/logout-all").header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk());
    }

    @Test
    void refreshTokenInBodyDoesNotAuthenticateLogoutAll() throws Exception {
        mvc.perform(post("/api/v1/auth/logout-all").contentType(MediaType.APPLICATION_JSON)
                        .content(body(firstSession.getToken())))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.message").value("Authentication is required"));
        assertNoSessionsRevoked();
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "malformed", "expired", "refresh-token"})
    void rejectsMissingOrInvalidAccessToken(String scenario) throws Exception {
        var request = post("/api/v1/auth/logout-all");
        String token = switch (scenario) {
            case "expired" -> Jwts.builder().subject(user.getId().toString()).claim("role", "USER")
                    .issuer(properties.getAccessIssuer()).audience().add(properties.getAccessAudience()).and()
                    .expiration(Date.from(Instant.now().minusSeconds(60)))
                    .signWith(jwtService.getAccessSecretKey()).compact();
            case "refresh-token" -> firstSession.getToken();
            default -> "invalid-token";
        };
        if (!"missing".equals(scenario)) {
            request.header("Authorization", "Bearer " + token);
        }
        mvc.perform(request).andExpect(status().isUnauthorized());
        assertNoSessionsRevoked();
    }

    private User createUser(String email) {
        User result = new User();
        result.setEmail(email);
        result.setPasswordHash("unused-in-token-authentication-tests");
        result.setActive(true);
        result.setRole(UserRole.USER);
        return users.saveAndFlush(result);
    }

    private JwtService.RefreshTokenResult createSession(User owner) {
        var result = jwtService.generateRefreshToken(owner);
        sessionsService.createRefreshSession(result.getSessionId(), owner, authService.hashToken(result.getToken()),
                jwtService.verifyRefreshToken(result.getToken()).getExpiration().toInstant());
        return result;
    }

    private void assertNoSessionsRevoked() {
        sessions.findAll().forEach(session -> assertNull(session.getRevokedAt()));
    }

    private String body(String token) {
        return "{\"refreshToken\":\"" + token + "\"}";
    }
}
