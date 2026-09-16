package com.example.authservice.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class LoginThrottledException extends GlobalException {
    private final long retryAfterSeconds;

    public LoginThrottledException(long retryAfterSeconds) {
        super("Too many login attempts. Please try again later.", HttpStatus.TOO_MANY_REQUESTS);
        this.retryAfterSeconds = retryAfterSeconds;
    }
}
