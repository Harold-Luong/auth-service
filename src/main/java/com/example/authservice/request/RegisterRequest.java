package com.example.authservice.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Email must be valid")
        @Size(max = 255, message = "Email must not exceed 255 characters")
        String email,
        @NotBlank(message = "Password is required")
        String password) {
    public RegisterRequest {
        email = email == null ? null : email.trim();
    }
}
