package com.nhnacademy._vidiagateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

@Component
@Slf4j
public class JwtAuthorizationHeaderFilter extends AbstractGatewayFilterFactory<JwtAuthorizationHeaderFilter.Config> {
    private static final String SECRET_KEY = "qwertyujhgfdsazxcvbnjhgfdsqwertyuhgfdsazxcvb";
    @Value("${auth.cookie.secure}")
    private boolean secure;
    public JwtAuthorizationHeaderFilter() {
        super(Config.class);
    }

    public static class Config {
        // application.properties에서 받을 config 있으면 추가 가능
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();

            // 1. Authorization 헤더 확인
            List<String> authHeaders = request.getHeaders().get(HttpHeaders.AUTHORIZATION);
            String path = request.getURI().getPath();
            boolean isProtectedPath = path.startsWith("/users");


            if (authHeaders == null || authHeaders.isEmpty() || authHeaders.get(0).isEmpty()) {
                if (isProtectedPath) {
                    log.warn("Unauthorized access to protected path {}, redirecting to login.", path);
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }


                String guestId = exchange.getRequest().getHeaders().getFirst("X-Guest-Id");
                if (guestId == null) {
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }

                log.warn("Authorization header is missing");
                ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                        .header("X-Guest-Id", guestId) // 혹은 "anonymous" 또는 헤더 자체를 안 보낼 수도 있음
                        .build();
                return chain.filter(exchange.mutate().request(mutatedRequest).build());
            }
            log.info("1");

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.warn("Invalid Authorization header");
                return chain.filter(exchange);
            }
            log.info("2");

            String accessToken = authHeader.substring(7); // "Bearer " 제거

            try {
                SecretKey key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
                Claims claims = Jwts.parser()
                        .verifyWith(key)
                        .build()
                        .parseClaimsJws(accessToken)
                        .getBody();
                Date expiration = claims.getExpiration();

// 현재 시간
                Date now = new Date();

// 로그 출력
                log.info("JWT 만료시간(exp): {}", expiration);
                log.info("현재 서버시간: {}", now);

// 만료 여부 직접 확인도 가능
                if (expiration != null && expiration.before(now)) {
                    log.warn("Token is expired by exp claim");
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                    return exchange.getResponse().setComplete();
                }

                Long userId = claims.get("id", Long.class); // JWT payload에 userId가 있어야 함
                String role = claims.get("roles", String.class); // <-- 토큰에서 'role' 클레임 추출
                log.info("Extracted userId from JWT: {}{}", userId, role);
                log.debug("Extracted userId from JWT: {}{}", userId, role);

                if (path.startsWith("/admin")) {
                    if (!"ADMIN".equals(role)) {
                        log.warn("Forbidden: user {} tried to access admin path {}", userId, path);
                        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                        return exchange.getResponse().setComplete();
                    }
                }

                ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                        .header("X-User-Id", userId.toString())
                        .header("X-User-Role", role)
                        .build();

                return chain.filter(exchange.mutate().request(mutatedRequest).build());
            }  catch (io.jsonwebtoken.ExpiredJwtException e) {
                log.warn("JWT expired: {}", e.getMessage());
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                return exchange.getResponse().setComplete();
            } catch (Exception e) {
                log.error("JWT validation failed: {}", e.getMessage());
                return chain.filter(exchange); // 필요 시 401 에러 반환 가능
            }
        };
    }
}

