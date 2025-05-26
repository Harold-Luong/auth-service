package com.ecommerce.auth.dto;

public record AuthResponse(String accessToken, String refreshToken, String userName) {}
