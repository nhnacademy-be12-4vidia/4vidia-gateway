package com.nhnacademy._vidiagateway.filter;

import com.nhnacademy._vidiagateway.dto.UserGatewayResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.UUID;

@Component
@Slf4j
public class JwtAuthorizationHeaderFilter extends AbstractGatewayFilterFactory<JwtAuthorizationHeaderFilter.Config> {
    private final WebClient webClient;

    @Value("${auth.cookie.secure}")
    private boolean secure;

    public JwtAuthorizationHeaderFilter(WebClient.Builder webClientBuilder) {
        super(Config.class);
        this.webClient = webClientBuilder.build();
    }

    public static class Config {
        // application.properties에서 받을 config 있으면 추가 가능
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();
            log.info(path);

            MultiValueMap<String, HttpCookie> cookies = request.getCookies();
            HttpCookie ses = cookies.getFirst("SES");
            HttpCookie aut = cookies.getFirst("AUT");

            boolean isProtectedPath = path.startsWith("/users");

            String guestId = request.getHeaders().getFirst("X-Guest-Id");
            if (guestId == null) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            String incomingTraceId = request.getHeaders().getFirst("X-Trace-Id");
            String traceId = (incomingTraceId == null || incomingTraceId.isEmpty()) ? UUID.randomUUID().toString() : incomingTraceId;

            // 보호 API인데 로그인 안됨
            if (isProtectedPath && (ses == null || aut == null)) {
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }



            // 로그인 상태
            if (ses != null && aut != null) {
                return validateWithAuthServer(ses.getValue(), aut.getValue())
                        .flatMap(userInfo -> {

                            // 🚫 휴면 계정
                            if ("DORMANT".equals(userInfo.status())) {
                                log.info("휴먼유저");
                                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                                exchange.getResponse().getHeaders()
                                        .add("X-Error-Code", "DORMANT_USER");
                                return exchange.getResponse().setComplete();
                            }

                            // ⚠️ 임시 계정 → 필수 정보 입력만 허용
                            if ("TEMP".equals(userInfo.status())
                                    && !(path.startsWith("/users/complete-profile")||path.startsWith("/users/name")||path.startsWith("/users/role")||path.startsWith("/auth/logout"))) {
                                log.info("임시유저");
                                exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                                exchange.getResponse().getHeaders()
                                        .add("X-Error-Code", "TEMP_USER");
                                return exchange.getResponse().setComplete();
                            }

                            // ✅ 정상 사용자 → 헤더 주입
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
                        .onErrorResume(e -> {
                            exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                            return exchange.getResponse().setComplete();
                        });
            }

            // 비로그인 + 비보호 API
            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("X-Guest-Id", guestId)
                    .header("X-Trace-Id", traceId)
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        };
    }

    /*
     * auth서버에서 토큰 검증하도록
     */
    private Mono<UserGatewayResponse> validateWithAuthServer(String ses, String aut) {
        return webClient.post()
                .uri("lb://4vidia-auth/validate")
                .cookie("SES", ses)
                .cookie("AUT", aut)
                .exchangeToMono(response -> {
                    if (response.statusCode().is2xxSuccessful()) {
                        return response.bodyToMono(UserGatewayResponse.class);
                    }

                    if (response.statusCode() == HttpStatus.UNAUTHORIZED) {
                        return Mono.empty(); // 🔥 예외 아님
                    }

                    return Mono.error(new IllegalStateException(
                            "Unexpected auth response: " + response.statusCode()));
                });
    }
}

