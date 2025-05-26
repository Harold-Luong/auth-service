package com.ecommerce.auth.exception;

import com.ecommerce.auth.exception.common.BaseException;
import com.ecommerce.auth.exception.common.ErrorCode;

public class ConstraintViolationException extends BaseException {
    public ConstraintViolationException() {
        super(ErrorCode.VALIDATION_FAILED);
    }

    public ConstraintViolationException(String message) {
        super(ErrorCode.VALIDATION_FAILED, message);
    }
}
