package com.ecommerce.auth.security;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import java.util.*;

@Component
public class JwtAuthorizationFilter extends AbstractGatewayFilterFactory<JwtAuthorizationFilter.Config> {
    private static final Logger log = LoggerFactory.getLogger(JwtAuthorizationFilter.class);
    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    public JwtAuthorizationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            // Lấy token từ header
            String token = jwtTokenProvider.extractToken(exchange.getRequest());
            if (token == null) {
                return unauthorized(exchange, "Missing authorization token");
            }

            // Kiểm tra token hợp lệ
            if (!jwtTokenProvider.validateToken(token)) {
                return unauthorized(exchange, "Invalid token");
            }

            // Kiểm tra token hết hạn
            if (jwtTokenProvider.isTokenExpired(token)) {
                return unauthorized(exchange, "Token has expired");
            }

            // Lấy các role yêu cầu từ metadata
            Set<String> requiredRoles = extractRequiredRoles(exchange);
            if (requiredRoles == null || requiredRoles.isEmpty()) {
                return forbidden(exchange, "Insufficient permissions");
            }

            // Kiểm tra role trong token, cần ít nhất 1 role
            List<String> userRoles = jwtTokenProvider.extractRoles(token);
            boolean hasPermission = userRoles.stream().anyMatch(requiredRoles::contains);
            if (!hasPermission) {
                return forbidden(exchange, "Insufficient permissions");
            }

            // Gắn thông tin user vào request header
            String username = jwtTokenProvider.extractUsername(token);

            String id = jwtTokenProvider.extractUserId(token);

            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header("X-User-id", id)
                    .header("X-User-Name", username)
                    .header("X-User-Roles", String.join(",", userRoles))
                    .header("X-Internal-Auth", "my-secret-token")
                    .build();
            ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();
            return chain.filter(mutatedExchange);
        };
    }

    private Set<String> extractRequiredRoles(ServerWebExchange exchange) {
        Route route = exchange.getAttribute(ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR);
        Map<String, Object> metadata = route.getMetadata();
        if (metadata == null) return null;

        Object roles = metadata.get("required-roles");
        if (roles instanceof Map<?, ?> mapRoles) {
            return mapRoles.values().stream()
                    .filter(obj -> obj instanceof String)
                    .map(obj -> (String) obj)
                    .collect(Collectors.toSet());
        }
        return null;
    }

    private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
        log.error(message);
        exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
        return exchange.getResponse().setComplete();
    }

    private Mono<Void> forbidden(ServerWebExchange exchange, String message) {
        log.error(message);
        exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
        return exchange.getResponse().setComplete();
    }

    public static class Config {
    }
}