package com.ecommerce.auth.exception;

import com.ecommerce.auth.exception.common.BaseException;
import com.ecommerce.auth.exception.common.ErrorCode;

public class RefreshTokenException extends BaseException {

    public RefreshTokenException() {
        super(ErrorCode.INVALID_REFRESH_TOKEN);
    }

    public RefreshTokenException(ErrorCode errorCode, String message) {
        super(errorCode, message);
    }
}

