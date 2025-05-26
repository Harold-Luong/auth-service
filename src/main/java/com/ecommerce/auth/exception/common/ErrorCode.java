package com.ecommerce.auth.exception.common;

import org.springframework.http.HttpStatus;

public enum ErrorCode {

    // 400 - BAD REQUEST
    INVALID_REQUEST(HttpStatus.BAD_REQUEST, "Invalid request data"),

    // 401 - UNAUTHORIZED
    INVALID_REFRESH_TOKEN(HttpStatus.UNAUTHORIZED, "Invalid or expired refresh token"),
    BAD_CREDENTIALS(HttpStatus.UNAUTHORIZED, "Invalid username or password"),

    // 403 - FORBIDDEN
    FORBIDDEN(HttpStatus.FORBIDDEN, "Access denied"),
    ACCOUNT_DISABLED(HttpStatus.FORBIDDEN, "Account disable"),

    // 404 - NOT FOUND
    USER_NOT_FOUND(HttpStatus.NOT_FOUND, "User not found"),

    // 409 - CONFLICT
    ALREADY_EXISTS(HttpStatus.CONFLICT, "Already exists"),

    // 422 - UNPROCESSABLE ENTITY
    VALIDATION_FAILED(HttpStatus.UNPROCESSABLE_ENTITY, "Validation failed"),

    // 500 - INTERNAL SERVER ERROR
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "Internal server error");

    private final HttpStatus httpStatus;
    private final String message;

    ErrorCode(HttpStatus httpStatus, String message) {
        this.httpStatus = httpStatus;
        this.message = message;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public int getCode() {
        return httpStatus.value();
    }

    public String getMessage() {
        return message;
    }
}
