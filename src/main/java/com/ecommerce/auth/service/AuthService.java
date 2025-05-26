package com.ecommerce.auth.service;

import com.ecommerce.auth.dto.AuthRequest;
import com.ecommerce.auth.dto.AuthResponse;
import com.ecommerce.auth.dto.RegisterRequest;
import com.ecommerce.auth.entity.RefreshToken;
import com.ecommerce.auth.entity.Role;
import com.ecommerce.auth.entity.User;
import com.ecommerce.auth.exception.AlreadyExistsException;
import com.ecommerce.auth.kafka.UserCreatedEvent;
import com.ecommerce.auth.kafka.UserProducer;
import com.ecommerce.auth.repository.UserRepository;
import com.ecommerce.auth.security.JwtAuthorizationFilter;
import com.ecommerce.auth.security.JwtTokenProvider;
import jakarta.transaction.Transactional;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthorizationFilter.class);

    @Autowired
    UserRepository userRepository;

    @Autowired
    JwtTokenProvider jwtTokenProvider;

    @Autowired
    PasswordEncoder passwordEncoder;

    @Autowired
    RefreshTokenService refreshTokenService;

    @Autowired
    UserProducer userProducer;

    public AuthResponse authenticate(AuthRequest request) {
        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new UsernameNotFoundException("Invalid credentials"));

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new BadCredentialsException("Invalid credentials");
        }

        if (user.isDeleted()) {
            throw new DisabledException("Account is deleted.");
        }

        Set<Role> role = user.getRoles();
        String accessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getUsername(), role);
        // Check nếu user đã có refresh token còn hạn, dùng lại
        Optional<RefreshToken> existingToken = refreshTokenService.findValidByUser(user);
        String refreshToken = existingToken.map(RefreshToken::getToken)
                .orElseGet(() -> refreshTokenService.createRefreshToken(user).getToken());
        log.info("User '{}' logged in successfully", user.getUsername());

        return new AuthResponse(accessToken, refreshToken, user.getUsername());
    }

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new AlreadyExistsException("Username đã tồn tại");
        }

        User user = User.builder()
                .username(request.username())
                .password(passwordEncoder.encode(request.password()))
                // mặc định đăng ký là role USER
                .roles(new HashSet<>(List.of(Role.USER)))
                .build();

        User userDB = userRepository.save(user);
        UUID userId = userDB.getId();

        UserCreatedEvent event = new UserCreatedEvent(
                userId, user.getUsername(),
                request.fullName(), request.email(), request.phoneNumber(),
                request.address(), request.dayOfBirth(), request.avatar()
        );

        userProducer.sendUserCreatedEvent(event);
        log.info("User registered with ID: {}", userId);
        log.info("Sending UserCreatedEvent to Kafka: {}", event);

        String accessToken = jwtTokenProvider.generateAccessToken(userId, user.getUsername(), user.getRoles());
        String refreshToken = refreshTokenService.createRefreshToken(user).getToken();

        return new AuthResponse(accessToken, refreshToken, user.getUsername());
    }

    public void changePassword(String username, String oldPassword, String newPassword) {
        if (oldPassword.equals(newPassword)) {
            throw new AlreadyExistsException("Mật khẩu mới không được trùng với mật khẩu cũ");
        }

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Không tìm thấy người dùng"));

        if (!passwordEncoder.matches(oldPassword, user.getPassword())) {
            throw new BadCredentialsException("Mật khẩu cũ không đúng");
        }

        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }
}
