package com.ecommerce.auth.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "spring.security.jwt")
public class JwtConfig {

    private String secret;
    private long expiration;
    private long refreshExpiration;
    private String header;
    private String prefix;
}
