package com.ecommerce.auth.controller;

import com.ecommerce.auth.config.CustomUserDetails;
import com.ecommerce.auth.config.CustomUserDetailsService;
import com.ecommerce.auth.dto.RoleAssignmentRequest;
import com.ecommerce.auth.dto.UserInfoResponse;
import com.ecommerce.auth.entity.User;
import com.ecommerce.auth.repository.UserRepository;
import com.ecommerce.auth.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/test")
public class TestGetUserController {

    @Autowired
    private CustomUserDetailsService customUserDetailsService;
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthService authService;

    @GetMapping("/me")
    public ResponseEntity<UserInfoResponse> getUser(@AuthenticationPrincipal CustomUserDetails userDetails) {
        String username = userDetails.getUsername();
        User user = userRepository.findByUsername(username).orElse(null);
        return ResponseEntity.ok(UserInfoResponse.fromEntity(user));
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/assign-role")
    public ResponseEntity<Void> assignRole(@Valid @RequestBody RoleAssignmentRequest request) {
        authService.assignRole(request.userId(), request.roles());
        return ResponseEntity.ok().build();
    }
}
