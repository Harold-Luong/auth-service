package com.example.authservice;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.example.authservice.entity.User;
import com.example.authservice.enums.UserRole;
import com.example.authservice.repository.RefreshSessionsRepository;
import com.example.authservice.repository.UserRepository;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import tools.jackson.databind.ObjectMapper;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.hamcrest.Matchers.matchesPattern;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(properties = {
        "auth.login-throttle.account-max-attempts=3",
        "auth.login-throttle.ip-max-attempts=4",
        "auth.login-throttle.window=1m"
})
@AutoConfigureMockMvc
class LoginThrottleApiTests {
    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper mapper;
    @Autowired private UserRepository users;
    @Autowired private RefreshSessionsRepository sessions;
    @Autowired private PasswordEncoder encoder;

    private static final AtomicInteger sequence = new AtomicInteger();
    private final Logger auditLogger = (Logger) LoggerFactory.getLogger("auth.login.audit");
    private ListAppender<ILoggingEvent> audit;
    private User user;
    private String ip;

    @BeforeEach
    void setUp() {
        sessions.deleteAll();
        users.deleteAll();
        int id = sequence.incrementAndGet();
        ip = "192.0.2." + id;
        user = new User();
        user.setEmail("throttle" + id + "@example.com");
        user.setPasswordHash(encoder.encode("correct-secret"));
        user.setActive(true);
        user.setRole(UserRole.USER);
        user = users.saveAndFlush(user);
        audit = new ListAppender<>();
        audit.start();
        auditLogger.addAppender(audit);
    }

    @AfterEach
    void tearDown() {
        auditLogger.detachAppender(audit);
        audit.stop();
    }

    @Test
    void accountLimitSurvivesAuthenticationTransactionRollbacksAndIpChanges() throws Exception {
        for (int i = 1; i <= 3; i++) {
            login(" " + user.getEmail().toUpperCase(java.util.Locale.ROOT) + " ", "wrong-secret", "198.51.100." + i)
                    .andExpect(status().isUnauthorized());
        }
        login(user.getEmail(), "correct-secret", ip)
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", matchesPattern("[1-9][0-9]*")))
                .andExpect(jsonPath("$.code").value("429"))
                .andExpect(jsonPath("$.message").value("Too many login attempts. Please try again later."));
        assertEquals(0, sessions.count());
        assertEquals(3, audit.list.stream().filter(e -> e.getFormattedMessage().contains("event=login_failed")).count());
        assertTrue(audit.list.getLast().getFormattedMessage().contains("event=login_throttled"));
    }

    @Test
    void ipLimitAppliesAcrossAccountsAndIgnoresSpoofedForwardingHeaders() throws Exception {
        for (int i = 0; i < 4; i++) {
            login("unknown" + i + user.getEmail(), "wrong-secret", ip)
                    .andExpect(status().isUnauthorized());
        }
        mvc.perform(post("/api/v1/auth/login")
                        .with(request -> { request.setRemoteAddr(ip); return request; })
                        .header("X-Forwarded-For", "203.0.113.99")
                        .header("Forwarded", "for=203.0.113.99")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(Map.of("email", user.getEmail(), "password", "correct-secret"))))
                .andExpect(status().isTooManyRequests());
        assertEquals(0, sessions.count());
        assertTrue(audit.list.getLast().getFormattedMessage().contains("ip=" + ip));
        assertFalse(audit.list.getLast().getFormattedMessage().contains("203.0.113.99"));
        login(user.getEmail(), "correct-secret", "203.0.113.1").andExpect(status().isOk());
    }

    @Test
    void successfulLoginDoesNotResetAttemptBudgets() throws Exception {
        login(user.getEmail(), "wrong-secret", ip).andExpect(status().isUnauthorized());
        login(user.getEmail(), "correct-secret", ip).andExpect(status().isOk());
        login(user.getEmail(), "wrong-secret", ip).andExpect(status().isUnauthorized());
        login(user.getEmail(), "correct-secret", ip).andExpect(status().isTooManyRequests());
        assertEquals(1, sessions.count());
    }

    @Test
    void auditsUnknownPasswordAndInactiveFailuresWithoutCredentials() throws Exception {
        login("unknown-" + user.getEmail(), "wrong-secret", ip).andExpect(status().isUnauthorized());
        login(user.getEmail(), "wrong-secret", ip).andExpect(status().isUnauthorized());
        user.setActive(false);
        users.saveAndFlush(user);
        login(user.getEmail(), "correct-secret", ip).andExpect(status().isForbidden());
        assertEquals(3, audit.list.size());
        String messages = audit.list.stream().map(ILoggingEvent::getFormattedMessage).reduce("", (a, b) -> a + "\n" + b);
        assertTrue(messages.contains("reason=UNKNOWN_ACCOUNT"));
        assertTrue(messages.contains("reason=INVALID_PASSWORD"));
        assertTrue(messages.contains("reason=INACTIVE_ACCOUNT"));
        assertTrue(messages.contains("accountHash="));
        assertFalse(messages.contains(user.getEmail()));
        assertFalse(messages.contains("wrong-secret"));
        assertFalse(messages.contains("correct-secret"));
        assertFalse(messages.contains(user.getPasswordHash()));
    }

    private ResultActions login(String email, String password, String remoteIp) throws Exception {
        return mvc.perform(post("/api/v1/auth/login")
                .with(request -> { request.setRemoteAddr(remoteIp); return request; })
                .contentType(MediaType.APPLICATION_JSON)
                .content(mapper.writeValueAsString(Map.of("email", email, "password", password))));
    }
}
