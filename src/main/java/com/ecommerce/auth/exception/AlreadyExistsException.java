package com.ecommerce.auth.exception;

import com.ecommerce.auth.exception.common.BaseException;
import com.ecommerce.auth.exception.common.ErrorCode;

public class AlreadyExistsException extends BaseException {
    public AlreadyExistsException() {
        super(ErrorCode.ALREADY_EXISTS);
    }

    public AlreadyExistsException(String message) {
        super(ErrorCode.ALREADY_EXISTS, message);
    }
}
