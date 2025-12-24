package com.nhnacademy._vidiagateway.dto;

import lombok.Getter;

// user-service -> auth
public record UserInfoResponse(
        Long id,
        @Getter
        String email,
        @Getter
        String password,
        @Getter
        String roles,        // "ROLE_USER", "ROLE_ADMIN"
        @Getter
        String status
) {}