package com.example.authservice.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class GlobalException extends RuntimeException {
    private final String code;
    private final HttpStatus status;

    public GlobalException(String message, HttpStatus httpStatus) {
        super(message);
        this.code = httpStatus.value() + "";
        this.status = httpStatus;
    }
}
