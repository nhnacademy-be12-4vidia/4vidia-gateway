package com.nhnacademy._vidiagateway.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.LocalDateTime;
import java.time.ZoneOffset;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiResponse<T>(
        Header header,
        T data
) {

    // 2. 헤더 (성공 여부, 코드, 메시지)
    public record Header(
            boolean isSuccessful,
            int resultCode, // HTTP Status
            String resultMessage, // 사용자 메시지
            String errorCode, // 서비스 에러 코드
            LocalDateTime timestamp
    ) {}

    /**
     * [성공] 데이터를 포함한 성공 응답 (ResponseBodyAdvice에서 사용)
     */
    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(
                new Header(true, 200, "SUCCESS", null, LocalDateTime.now(ZoneOffset.UTC)),
                data
        );
    }

    /**
     * [실패] 에러 코드와 메시지를 포함한 실패 응답 (GlobalExceptionHandler에서 사용)
     */
    public static <T> ApiResponse<T> fail(int status, String message, String errorCode) {
        return new ApiResponse<>(
                new Header(false, status, message, errorCode, LocalDateTime.now()),  null // 실패 시 데이터는 보통 없음
        );
    }
}