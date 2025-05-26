package com.ecommerce.auth.controller;

import com.ecommerce.auth.dto.AuthRequest;
import com.ecommerce.auth.dto.AuthResponse;
import com.ecommerce.auth.dto.LogoutRequest;
import com.ecommerce.auth.dto.RefreshTokenRequest;
import com.ecommerce.auth.dto.RegisterRequest;
import com.ecommerce.auth.dto.RoleAssignmentRequest;
import com.ecommerce.auth.entity.RefreshToken;
import com.ecommerce.auth.entity.Role;
import com.ecommerce.auth.entity.User;
import com.ecommerce.auth.exception.RefreshTokenException;
import com.ecommerce.auth.security.JwtTokenProvider;
import com.ecommerce.auth.service.AuthService;
import com.ecommerce.auth.service.RefreshTokenService;
import jakarta.validation.Valid;
import java.util.List;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Validated
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private RefreshTokenService refreshTokenService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        AuthResponse authResponse = authService.register(request);
        return ResponseEntity.ok(authResponse);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
        return ResponseEntity.ok(authService.authenticate(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        RefreshToken refreshToken = refreshTokenService
                .findByToken(request.refreshToken())
                .map(refreshTokenService::verifyExpiration)
                .orElseThrow(RefreshTokenException::new);

        User user = refreshToken.getUser();
        Set<Role> role = user.getRoles();
        String accessToken = jwtTokenProvider.generateAccessToken(user.getUsername(), role);

        return ResponseEntity.ok(new AuthResponse(
                accessToken,
                request.refreshToken()
        ));
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestBody LogoutRequest request) {
        refreshTokenService.deleteByToken(request.refreshToken());
        return ResponseEntity.noContent().build();
    }



}
