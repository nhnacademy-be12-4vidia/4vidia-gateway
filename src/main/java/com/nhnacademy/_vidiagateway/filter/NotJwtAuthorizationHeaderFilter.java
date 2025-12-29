package com.nhnacademy._vidiagateway.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nhnacademy._vidiagateway.dto.ApiResponse;
import com.nhnacademy._vidiagateway.dto.UserGatewayResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
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
public class NotJwtAuthorizationHeaderFilter extends AbstractGatewayFilterFactory<NotJwtAuthorizationHeaderFilter.Config>{
    public static class Config {
        // application.properties에서 받을 config 있으면 추가 가능
    }

    public NotJwtAuthorizationHeaderFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();
            log.info(path);

            String incomingTraceId = request.getHeaders().getFirst("X-Trace-Id");
            String traceId = (incomingTraceId == null || incomingTraceId.isEmpty()) ? UUID.randomUUID().toString() : incomingTraceId;

            ServerHttpRequest mutatedRequest = request.mutate()
                    .header("X-Trace-Id", traceId)
                    .build();

            //reactor는 내부에서 찍어야해
            return Mono.deferContextual(ctx -> {
                        log.info("NotJwt filter pass path={}", path);
                        return chain.filter(exchange.mutate().request(mutatedRequest).build())
                                .onErrorResume(e ->
                                        writeFailResponse(
                                                exchange,
                                                HttpStatus.FORBIDDEN,
                                                "접근할 수 없습니다",
                                                "FORBIDDEN"
                                        )
                                );

                    })
                    // 여기서 Context 주입***
                    .contextWrite(context -> context.put("traceId", traceId));        };
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
            bytes = new ObjectMapper().writeValueAsBytes(response);
        } catch (Exception e) {
            exchange.getResponse().setStatusCode(status);
            return exchange.getResponse().setComplete();
        }

        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

        DataBufferFactory bufferFactory = exchange.getResponse().bufferFactory();
        DataBuffer buffer = bufferFactory.wrap(bytes);

        return exchange.getResponse().writeWith(Mono.just(buffer));
    }

}
