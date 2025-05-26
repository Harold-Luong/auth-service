package com.ecommerce.auth.exception;

import com.ecommerce.auth.exception.common.ErrorCode;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
public class ErrorResponse {
    private int code;
    private String message;

    public ErrorResponse(ErrorCode errorCode) {
        this.code = errorCode.getCode();
        this.message = errorCode.getMessage();
    }

    public ErrorResponse(String message, ErrorCode errorCode) {
        this.code = errorCode.getCode();
        this.message = message + errorCode.getMessage();
    }
    public ErrorResponse(int code, String message) {
        this.code = code;
        this.message = message;
    }
}
