package com.ecommerce.auth.dto;

import com.ecommerce.auth.entity.Role;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import java.util.Set;

public record RoleAssignmentRequest (

    @NotNull(message = "User ID cannot be null")
    Long userId,

    @NotNull(message = "Roles cannot be null")
    @Size(min = 1, message = "At least one role must be assigned")
    Set<Role> roles)
    { }
