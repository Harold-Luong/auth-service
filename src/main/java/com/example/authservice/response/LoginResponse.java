package com.example.authservice.response;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({ "message", "data" })
public record LoginResponse(String message, Data data) {
    @JsonPropertyOrder({ "tokenType", "accessToken", "refreshToken", "accessTokenExpiresIn", "refreshTokenExpiresIn" })
    public static record Data(
            String tokenType,
            String accessToken,
            String refreshToken,
            Long accessTokenExpiresIn,
            Long refreshTokenExpiresIn) {
    }
}
