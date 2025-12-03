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
import java.security.Key;
import java.util.UUID;

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
            if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                String guestId;
                HttpCookie guestCookie = request.getCookies().getFirst("guest_id"); // 1) 기존 쿠키 확인

                if (guestCookie != null) {
                    // 1-1. 기존 쿠키가 있으면 그 값을 사용
                    guestId = guestCookie.getValue();
                    log.info("GUEST request with existing ID: {}", guestId);
                } else {
                    // 1-2. 쿠키가 없으면 새로운 UUID 생성
                    guestId = UUID.randomUUID().toString();

                    // 1-3. **응답에 Set-Cookie를 추가하여 클라이언트에게 전송**
                    ResponseCookie cookie = ResponseCookie.from("guest_id", guestId)
                            .maxAge(60 * 60 * 24 * 3) // 3일 유효기간
                            .path("/")
                            .httpOnly(true) // XSS 방지
                            .secure(secure) // HTTPS일 경우 Secure 설정
                            .sameSite("Lax") // CSRF 방지
                            .build();

                    exchange.getResponse().addCookie(cookie);
                    log.info("New GUEST ID generated: {}", guestId);
                }
                log.warn("Authorization header is missing");
                // 필요하면 여기서 예외 던짐
                ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                        .header("X-Guest-Id", "0") // 혹은 "anonymous" 또는 헤더 자체를 안 보낼 수도 있음
                        .header("X-Role", "GUEST")
                        .build();
                return chain.filter(exchange.mutate().request(mutatedRequest).build());
            }

            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                log.warn("Invalid Authorization header");
                return chain.filter(exchange);
            }

            String accessToken = authHeader.substring(7); // "Bearer " 제거

            try {
                // 2. JWT 검증
                SecretKey key = Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8));
                Claims claims = Jwts.parser()
                        .verifyWith(key)
                        .build()
                        .parseClaimsJws(accessToken)
                        .getBody();

                // 3. userId 추출
                Long userId = claims.get("id", Long.class); // JWT payload에 userId가 있어야 함
                String role = claims.get("role", String.class); // <-- 토큰에서 'role' 클레임 추출
                log.debug("Extracted userId from JWT: {}", userId);

                // 4. X-USER-ID 헤더로 추가
                ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                        .header("X-User-Id", userId.toString())
                        .header("X-Role", role)
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

