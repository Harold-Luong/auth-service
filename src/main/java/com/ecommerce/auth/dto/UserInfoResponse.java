package com.ecommerce.auth.dto;

import com.ecommerce.auth.entity.RefreshToken;
import com.ecommerce.auth.entity.User;
import java.util.Set;
import java.util.stream.Collectors;

public record UserInfoResponse(Long id, String username, String email, Set<String> refreshTokens, Set<String> roles) {
    public static UserInfoResponse fromEntity(User user) {
        if(user == null) return null;

        Set<String> roleNames = user.getRoles()
                .stream()
                .map(Enum::name)
                .collect(Collectors.toSet());
        Set<String> refreshTokens = user.getRefreshTokens()
                .stream()
                .map(RefreshToken::getToken)
                .collect(Collectors.toSet());

        return new UserInfoResponse(
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                refreshTokens,
                roleNames
        );
    }
}
