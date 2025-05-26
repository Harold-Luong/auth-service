package com.ecommerce.auth.service;

import com.ecommerce.auth.dto.AuthRequest;
import com.ecommerce.auth.dto.AuthResponse;
import com.ecommerce.auth.dto.RegisterRequest;
import com.ecommerce.auth.entity.RefreshToken;
import com.ecommerce.auth.entity.Role;
import com.ecommerce.auth.entity.User;
import com.ecommerce.auth.exception.UsernameAlreadyExistsException;
import com.ecommerce.auth.repository.UserRepository;
import com.ecommerce.auth.security.JwtTokenProvider;
import jakarta.transaction.Transactional;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    @Autowired
    UserRepository userRepository;

    @Autowired
    JwtTokenProvider jwtTokenProvider;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    RefreshTokenService refreshTokenService;

    public AuthResponse authenticate(AuthRequest request) {
        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new UsernameNotFoundException("Invalid credentials"));

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new BadCredentialsException("Invalid credentials");
        }

        Set<Role> role = user.getRoles();
        String accessToken = jwtTokenProvider.generateAccessToken(user.getUsername(), role);
        // Check nếu user đã có refresh token còn hạn, dùng lại
        Optional<RefreshToken> existingToken = refreshTokenService.findValidByUser(user);
        String refreshToken = existingToken.map(RefreshToken::getToken)
                .orElseGet(() -> refreshTokenService.createRefreshToken(user).getToken());

        return new AuthResponse(accessToken, refreshToken);
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new UsernameAlreadyExistsException();
        }

        User user = User.builder()
                .username(request.username())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .roles(new HashSet<>(List.of(Role.USER, Role.ADMIN)))
                .fullName(request.fullName())
                .build();
        userRepository.save(user);
        Set<Role> role = user.getRoles();
        String accessToken = jwtTokenProvider.generateAccessToken(user.getUsername(), role);
        String refreshToken = refreshTokenService.createRefreshToken(user).getToken();

        return new AuthResponse(accessToken, refreshToken);
    }

    @Transactional
    public void assignRole(Long userId, Set<Role> role) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));
        user.setRoles(role);
        userRepository.save(user);
    }
}
