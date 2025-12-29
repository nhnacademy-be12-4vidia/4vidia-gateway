package com.nhnacademy._vidiagateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy._vidiagateway.dto.ApiResponse;
import com.nhnacademy._vidiagateway.dto.UserGatewayResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Component
@Slf4j
public class JwtAuthorizationHeaderFilter
        extends AbstractGatewayFilterFactory<JwtAuthorizationHeaderFilter.Config> {

    private final WebClient webClient;
    private final ObjectMapper objectMapper;
    @Value("${auth.cookie.secure}")
    private boolean secure;

    public JwtAuthorizationHeaderFilter(WebClient.Builder webClientBuilder, ObjectMapper objectMapper) {
        super(Config.class);
        this.webClient = webClientBuilder.build();
        this.objectMapper = objectMapper;
    }

    public static class Config {
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();
            // 여기에 path로그 찍으면 안돼지
            log.info("{}", path);
            MultiValueMap<String, HttpCookie> cookies = request.getCookies();
            HttpCookie ses = cookies.getFirst("SES");
            HttpCookie aut = cookies.getFirst("AUT");

            boolean isProtectedPath = path.startsWith("/users");

            // ===== traceId 결정 =====
            String incomingTraceId = request.getHeaders().getFirst("X-Trace-Id");
            String traceId = (incomingTraceId == null || incomingTraceId.isBlank())
                    ? UUID.randomUUID().toString()
                    : incomingTraceId;

            // ===== guestId 체크 =====
            String guestId = request.getHeaders().getFirst("X-Guest-Id");
            if (guestId == null) {
                return writeFailResponse(
                        exchange,
                        HttpStatus.UNAUTHORIZED,
                        "게스트 ID가 필요합니다",
                        "GUEST_ID_REQUIRED"
                );
            }


            // ===== 보호 API + 비로그인 =====
            if (isProtectedPath && (ses == null || aut == null)) {
                return writeFailResponse(
                        exchange,
                        HttpStatus.UNAUTHORIZED,
                        "로그인이 필요합니다",
                        "AUTH_REQUIRED"
                );
            }


            // ===== 로그인 상태 =====
            if (ses != null && aut != null) {
                return validateWithAuthServer(ses.getValue(), aut.getValue(), traceId)
                        .flatMap(userInfo ->
                                Mono.deferContextual(ctx -> {
                                    log.info("{},{},{}", userInfo.id(), userInfo.getRoles(), userInfo.getStatus());

                                    log.info("JWT validated path={}, userId={}", path, userInfo.id());

                                    // 🚫 휴면 계정
                                    if ("DORMANT".equals(userInfo.status())&&!(path.startsWith("/auth/dormant/send-code")|| path.startsWith("/auth/dormant/verify")||path.startsWith("/users/name")|| path.startsWith("/users/role")|| path.startsWith("/auth/logout"))) {
                                        log.info("Dormant user");

                                        return writeFailResponse(
                                                exchange,
                                                HttpStatus.FORBIDDEN,
                                                "휴면 계정입니다",
                                                "DORMANT_USER"
                                        );
                                    }

                                    // ⚠️ 임시 계정
                                    if ("TEMP".equals(userInfo.status())
                                            && !(path.startsWith("/users/complete-profile")
                                            || path.startsWith("/users/name")
                                            || path.startsWith("/users/role")
                                            || path.startsWith("/auth/logout"))) {

                                        log.info("Temp user blocked");

                                        return writeFailResponse(
                                                exchange,
                                                HttpStatus.FORBIDDEN,
                                                "추가 정보 입력이 필요합니다",
                                                "TEMP_USER"
                                        );
                                    }


                                    // ✅ 정상 사용자
                                    ServerHttpRequest mutatedRequest = request.mutate()
                                            .header("X-User-Id", String.valueOf(userInfo.id()))
                                            .header("X-User-Role", userInfo.roles())
                                            .header("X-Guest-Id", guestId)
                                            .header("X-Trace-Id", traceId)
                                            .build();

                                    return chain.filter(
                                            exchange.mutate().request(mutatedRequest).build()
                                    );
                                })
                        )
                        .contextWrite(ctx -> ctx.put("traceId", traceId))
                        .onErrorResume(e ->
                                writeFailResponse(
                                        exchange,
                                        HttpStatus.UNAUTHORIZED,
                                        "인증 정보가 유효하지 않습니다",
                                        "INVALID_TOKEN"
                                )
                        );

            }

            // ===== 비로그인 + 비보호 API =====
            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("X-Guest-Id", guestId)
                    .header("X-Trace-Id", traceId)
                    .build();

            return Mono.deferContextual(ctx -> {
                        log.info("Guest access path={}", path);
                        return chain.filter(
                                exchange.mutate().request(mutatedRequest).build()
                        );
                    })
                    .contextWrite(ctx -> ctx.put("traceId", traceId));
        };
    }

    private Mono<UserGatewayResponse> validateWithAuthServer(String ses, String aut, String traceId) {
        return webClient.post()
                .uri("lb://4vidia-auth/internal/validate")
                .cookie("SES", ses)
                .cookie("AUT", aut)
                .header("X-Trace-Id", traceId)
                .exchangeToMono(response -> {
                    if (response.statusCode().is2xxSuccessful()) {
                        return response.bodyToMono(UserGatewayResponse.class);
                    }
                    if (response.statusCode() == HttpStatus.UNAUTHORIZED) {
                        return Mono.error(new IllegalStateException("UNAUTHORIZED"));
                    }
                    return Mono.error(new IllegalStateException(
                            "Unexpected auth response: " + response.statusCode()));
                });
    }

    private Mono<Void> writeFailResponse(
            ServerWebExchange exchange,
            HttpStatus status,
            String message,
            String errorCode
    ) {
        ApiResponse<Void> response =
                ApiResponse.fail(status.value(), message, errorCode);

        byte[] bytes;
        try {
            bytes = objectMapper.writeValueAsBytes(response);
        } catch (Exception e) {
            exchange.getResponse().setStatusCode(status);
            return exchange.getResponse().setComplete();
        }

        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        exchange.getResponse().getHeaders().setContentLength(bytes.length);

        DataBuffer buffer = exchange.getResponse()
                .bufferFactory()
                .wrap(bytes);

        return exchange.getResponse().writeWith(Mono.just(buffer));
    }


}
