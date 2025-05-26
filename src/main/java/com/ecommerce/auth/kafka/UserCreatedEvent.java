package com.ecommerce.auth.kafka;

import java.time.LocalDate;
import java.util.UUID;

public record UserCreatedEvent(
        UUID userId,
        String username,
        String fullName,
        String email,
        String phoneNumber,
        String address,
        LocalDate dayOfBirth,
        String avatar
) {}