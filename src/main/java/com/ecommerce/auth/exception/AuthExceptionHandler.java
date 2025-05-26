package com.ecommerce.auth.exception;

import com.ecommerce.auth.exception.common.BaseException;
import com.ecommerce.auth.exception.common.ErrorCode;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;

@RestControllerAdvice
public class AuthExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(AuthExceptionHandler.class);

    @ExceptionHandler(RefreshTokenException.class)
    public ResponseEntity<ErrorResponse> handleRefreshTokenException(RefreshTokenException ex) {
        ErrorCode errorCode = ex.getErrorCode();
        log.warn("Refresh token error: {}", errorCode.getMessage());
        return ResponseEntity.status(errorCode.getHttpStatus())
                .body(new ErrorResponse(errorCode));
    }

    // Xử lý exception custom kế thừa từ BaseException
    @ExceptionHandler(BaseException.class)
    public ResponseEntity<ErrorResponse> handleBaseException(BaseException ex) {
        log.warn("Handled BaseException: {}", ex.getMessage());
        ErrorCode errorCode = ex.getErrorCode();
        return ResponseEntity.status(errorCode.getHttpStatus())
                .body(new ErrorResponse(errorCode));
    }

    // Sai thông tin đăng nhập
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentialsException(BadCredentialsException ex) {
        log.warn("Bad Credentials: {}", ex.getMessage());
        return ResponseEntity.status(ErrorCode.BAD_CREDENTIALS.getHttpStatus())
                .body(new ErrorResponse(ErrorCode.BAD_CREDENTIALS));
    }

    // Tài khoản bị khóa, disabled hoặc không thể xác thực
    @ExceptionHandler({DisabledException.class, InternalAuthenticationServiceException.class})
    public ResponseEntity<ErrorResponse> handleDisabledException(Exception ex) {
        log.warn("Account disabled or internal error: {}", ex.getMessage());
        return ResponseEntity.status(ErrorCode.ACCOUNT_DISABLED.getHttpStatus())
                .body(new ErrorResponse(ErrorCode.ACCOUNT_DISABLED));
    }

    // Không có quyền truy cập
    @ExceptionHandler(AuthorizationDeniedException.class)
    public ResponseEntity<ErrorResponse> handleDAccessDenied(Exception ex) {
        log.warn("Access Denied: {}", ex.getMessage());
        return ResponseEntity.status(ErrorCode.FORBIDDEN.getHttpStatus())
                .body(new ErrorResponse(ErrorCode.FORBIDDEN));
    }

    // Không tìm thấy người dùng
    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUserNotFoundException(UsernameNotFoundException ex) {
        log.warn("User not found: {}", ex.getMessage());
        return ResponseEntity.status(ErrorCode.USER_NOT_FOUND.getHttpStatus())
                .body(new ErrorResponse(ErrorCode.USER_NOT_FOUND));
    }

    // field đã tồn tại
    @ExceptionHandler(AlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleAlreadyExists(AlreadyExistsException ex) {
        log.warn("Already exists: {}", ex.getMessage());
        return ResponseEntity.status(ErrorCode.ALREADY_EXISTS.getHttpStatus())
                .body(new ErrorResponse(ErrorCode.ALREADY_EXISTS.getCode(), ex.getMessage()));
    }

    // Các lỗi validate đầu vào
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ErrorResponse> handleValidationException(ConstraintViolationException ex) {
        log.warn("Validation failed: {}", ex.getMessage());
        return ResponseEntity.badRequest()
                .body(new ErrorResponse(ErrorCode.VALIDATION_FAILED));
    }

    // Bắt tất cả lỗi chưa xử lý
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGeneralException(Exception ex) {
        log.error("Unhandled Exception: {}", ex.getMessage(), ex);
        return ResponseEntity.status(ErrorCode.INTERNAL_SERVER_ERROR.getHttpStatus())
                .body(new ErrorResponse(ErrorCode.INTERNAL_SERVER_ERROR));
    }

    @ExceptionHandler(WebExchangeBindException.class)
    public ResponseEntity<Map<String, String>> handleValidationExceptions(WebExchangeBindException ex) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(error ->
                errors.put(error.getField(), error.getDefaultMessage())
        );
        return ResponseEntity.badRequest().body(errors);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgumentException(IllegalArgumentException ex) {
        log.error("Unhandled Exception: {}", ex.getMessage(), ex);
        return ResponseEntity.status(ErrorCode.INTERNAL_SERVER_ERROR.getHttpStatus())
                .body(new ErrorResponse(ErrorCode.INTERNAL_SERVER_ERROR.getCode(), ex.getMessage()));
    }
}