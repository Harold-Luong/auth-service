package com.example.authservice.response;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;

@JsonPropertyOrder({ "id", "email", "active", "role" })
public record UserResponse(
        Long id,
        String email,
        boolean active,
        String role) {
}
