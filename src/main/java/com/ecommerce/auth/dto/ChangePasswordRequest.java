package com.ecommerce.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record ChangePasswordRequest (
        @NotBlank(message = "Username không được để trống")
        String username,

        String oldPassword,

        @NotBlank(message = "Mật khẩu mới không được để trống")
        @Size(min = 6, message = "Mật khẩu phải có ít nhất 6 ký tự")
        @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d).*$", message = "Mật khẩu phải chứa ít nhất 1 chữ cái và 1 số")
        String newPassword)
{}
