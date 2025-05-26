package com.ecommerce.auth.exception;

import com.ecommerce.auth.exception.common.BaseException;
import com.ecommerce.auth.exception.common.ErrorCode;

public class UsernameAlreadyExistsException extends BaseException {
    public UsernameAlreadyExistsException() {
        super(ErrorCode.USERNAME_ALREADY_EXISTS);
    }

    public UsernameAlreadyExistsException(String message) {
        super(ErrorCode.USERNAME_ALREADY_EXISTS, message);
    }
}
