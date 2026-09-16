package com.example.authservice.controller;

import com.example.authservice.request.LoginRequest;
import com.example.authservice.request.RefreshTokenRequest;
import com.example.authservice.request.RegisterRequest;
import com.example.authservice.response.LoginResponse;
import com.example.authservice.response.AccessTokenResponse;
import com.example.authservice.response.UserResponse;
import com.example.authservice.service.AuthService;
import com.example.authservice.service.HealthCheckService;
import jakarta.validation.Valid;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final HealthCheckService healthCheckService;

    @GetMapping("/health-check")
    public ResponseEntity<Map<String, String>> healthCheck() {
        boolean connected = healthCheckService.isDatabaseConnected();
        return ResponseEntity.status(connected ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE)
                .body(Map.of("status", connected ? "UP" : "DOWN",
                        "database", connected ? "UP" : "DOWN"));
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        authService.register(request);
        return ResponseEntity.ok().body(Map.of("message", "User registered successfully!"));
    }

    @PostMapping("/login")
    public LoginResponse login(@Valid @RequestBody LoginRequest request, HttpServletRequest httpRequest) {
        return authService.login(request, httpRequest.getRemoteAddr());
    }

    @PostMapping("/refresh")
    public AccessTokenResponse refresh(
            @Valid @RequestBody RefreshTokenRequest request) {
        return authService.refresh(request.refreshToken());
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@Valid @RequestBody RefreshTokenRequest request) {
        authService.logout(request);
        return ResponseEntity.ok().body(Map.of("message", "Logged out successfully"));
    }

    @PostMapping("/logout-all")
    public ResponseEntity<?> logoutAll(
            Authentication authentication) {
        authService.logoutAll(authentication);
        return ResponseEntity.ok().body(Map.of("message", "All sessions logged out successfully"));
    }

    @GetMapping("/me")
    public UserResponse me(Authentication authentication) {
        return authService.me(authentication.getName());
    }
}
