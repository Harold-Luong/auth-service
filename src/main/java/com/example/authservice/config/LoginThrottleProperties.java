package com.example.authservice.config;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.time.DurationMin;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

@Getter
@Setter
@Validated
@ConfigurationProperties(prefix = "auth.login-throttle")
public class LoginThrottleProperties {
    @Min(1)
    private int accountMaxAttempts = 10;

    @Min(1)
    private int ipMaxAttempts = 50;

    @NotNull
    @DurationMin(seconds = 1)
    private Duration window = Duration.ofMinutes(15);

    // Includes both account keys and IP keys; active entries are never evicted to admit new keys.
    @Min(2)
    private int maxKeys = 10000;
}
