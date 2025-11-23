package com.nhnacademy._vidiagateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RouteLocatorConfig {
    @Bean
    public RouteLocator route(RouteLocatorBuilder builder) {
        return builder.routes()
                .route("bookstore-service",
                        r -> r.path("/api/v1/**")
                                .uri("lb://4vidia-bookstore-service"))
                .build();

    }
}
