package com.ecommerce.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import java.time.LocalDate;
import org.hibernate.validator.constraints.URL;

public record RegisterRequest (
        @NotBlank(message = "Username không được để trống")
        @Size(min = 6, max = 20, message = "Username phải từ 6 đến 20 ký tự")
        @Pattern(regexp = "^[a-zA-Z0-9]+$", message = "Username chỉ được chứa chữ cái và số")
        String username,

        @NotBlank(message = "Mật khẩu không được để trống")
        @Size(min = 6, message = "Mật khẩu phải có ít nhất 6 ký tự")
        @Pattern(regexp = "^(?=.*[A-Za-z])(?=.*\\d).*$",
                message = "Mật khẩu phải chứa ít nhất 1 chữ cái và 1 số")
        String password,

        @NotBlank(message = "Họ và tên không được để trống")
        @Size(max = 100, message = "Họ và tên không được vượt quá 100 ký tự")
        @Pattern(regexp = "^[\\p{L} ]+$", message = "Họ và tên chỉ được chứa chữ cái và khoảng trắng")
        String fullName,

        @NotBlank(message = "Email không được để trống")
        @Email(message = "Email không hợp lệ")
        @Size(max = 100, message = "Email không được vượt quá 100 ký tự")
        String email,

        @NotBlank(message = "Số điện thoại không được để trống")
        @Size(min = 9, max = 15, message = "Số điện thoại phải từ 9 đến 15 ký tự")
        @Pattern(regexp = "^(\\+\\d{1,3})?\\d{9,15}$",
                message = "Số điện thoại không hợp lệ. Ví dụ hợp lệ: +84123456789 hoặc 0123456789")
        String phoneNumber,

        @Size(max = 255, message = "Địa chỉ không được vượt quá 255 ký tự")
        String address,

        @NotNull(message = "Ngày sinh không được để trống")
        @Past(message = "Ngày sinh phải là ngày trong quá khứ")
        LocalDate dayOfBirth,

        @Size(max = 255, message = "URL ảnh đại diện không được vượt quá 255 ký tự")
        @URL(message = "URL ảnh đại diện không hợp lệ")
        String avatar
) {}