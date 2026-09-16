package com.example.authservice.config;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@Getter
@Setter
@ToString
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private String type;

    private Duration accessTokenExpiration;
    private Duration refreshTokenExpiration;

    private String accessSecret;
    private String refreshSecret;

    private String accessIssuer;
    private String accessAudience;

    private String refreshIssuer;
    private String refreshAudience;
}