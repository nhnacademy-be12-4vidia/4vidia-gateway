package com.nhnacademy._vidiagateway.filter;

import com.nhnacademy._vidiagateway.dto.UserInfoResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
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

            MultiValueMap<String, HttpCookie> cookies = exchange.getRequest().getCookies();
            HttpCookie ses = cookies.getFirst("SES");
            HttpCookie aut = cookies.getFirst("AUT");
            boolean isProtectedPath = path.startsWith("/users");

            String incomingTraceId = request.getHeaders().getFirst("X-Trace-Id");
            String traceId =
                    (incomingTraceId == null || incomingTraceId.isEmpty())
                            ? UUID.randomUUID().toString()
                            : incomingTraceId;

            if (isProtectedPath && (ses == null || aut == null)) {
                log.warn("Protected path {} accessed without SES/AUT cookies", path);
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            String guestId = exchange.getRequest().getHeaders().getFirst("X-Guest-Id");
            if (guestId == null) {
                log.warn("Missing X-Guest-Id header");
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            }

            if (ses != null && aut != null) {
                return validateWithAuthServer(ses.getValue(), aut.getValue())
                        .flatMap(userInfo -> forwardWithUserInfo(exchange, chain, request, userInfo, guestId, traceId))
                        .onErrorResume(Exception.class, e -> {
                            log.error("Gateway internal error", e);
                            exchange.getResponse().setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
                            return exchange.getResponse().setComplete();
                        });
            }

            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header("X-Guest-Id", guestId) // 혹은 "anonymous" 또는 헤더 자체를 안 보낼 수도 있음
                    .header("X-Trace-Id", traceId)
                    .build();
            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        };
    }

    /*
     * auth서버에서 토큰 검증하도록
     */
    private Mono<UserInfoResponse> validateWithAuthServer(String ses, String aut) {
        log.debug("Calling auth validate API");

        return webClient.post()
                .uri("lb://4vidia-auth/validate") // ⭐ 핵심
                .cookie("SES", ses)
                .cookie("AUT", aut)
                .retrieve()
                .onStatus(
                        status -> status == HttpStatus.UNAUTHORIZED,
                        response -> {
                            log.warn("Auth server returned 401");
                            return Mono.error(new RuntimeException("Unauthorized"));
                        }
                )
                .bodyToMono(UserInfoResponse.class)
                .doOnNext(user -> log.debug("Auth validated user: {}", user))
                .doOnError(err -> log.error("Auth validation error", err));
    }

    private Mono<Void> forwardWithUserInfo(
            ServerWebExchange exchange,
            GatewayFilterChain chain,
            ServerHttpRequest request,
            UserInfoResponse userInfo,
            String guestId,
            String traceId
    ) {
        log.debug("Forwarding request with user info");

        ServerHttpRequest mutatedRequest = request.mutate()
                .header("X-User-Id", String.valueOf(userInfo.id()))
                .header("X-User-Role", userInfo.roles())
                .header("X-Guest-Id", guestId)
                .header("X-Trace-Id", traceId)
                .build();

        return chain.filter(exchange.mutate().request(mutatedRequest).build());
    }


}

