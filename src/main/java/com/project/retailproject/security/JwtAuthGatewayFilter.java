package com.project.retailproject.security;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Component
public class JwtAuthGatewayFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;

    public JwtAuthGatewayFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    // ── Public paths — no token required ──
    private static final List<String> OPEN_PATHS = List.of(
            "/api/auth/"        // register + login
    );

    // ── Path → allowed roles (any logged-in user if not listed) ──
    // Matches your ROLE_ACCESS design. ADMIN is allowed everywhere (handled below).
    private static final Map<String, List<String>> PATH_ROLES = Map.ofEntries(
            Map.entry("/api/users",               List.of("ADMIN")),
            Map.entry("/api/audit-logs",          List.of("ADMIN", "COMPLIANCE_OFFICER")),
            Map.entry("/api/compliance-reports",  List.of("ADMIN", "COMPLIANCE_OFFICER", "STORE_MANAGER")),
            Map.entry("/api/kpi-reports",         List.of("ADMIN", "STORE_MANAGER")),
            Map.entry("/api/products",            List.of("ADMIN", "STORE_ASSOCIATE", "INVENTORY_MANAGER")),
            Map.entry("/api/catalogs",            List.of("ADMIN", "STORE_ASSOCIATE", "INVENTORY_MANAGER")),
            Map.entry("/api/inventory",           List.of("ADMIN", "INVENTORY_MANAGER", "STORE_MANAGER")),
            Map.entry("/api/purchase-orders",     List.of("ADMIN", "INVENTORY_MANAGER")),
            Map.entry("/api/sales",               List.of("ADMIN", "STORE_ASSOCIATE", "FINANCE_OFFICER", "STORE_MANAGER")),
            Map.entry("/api/invoices",            List.of("ADMIN", "FINANCE_OFFICER")),
            Map.entry("/api/payments",            List.of("ADMIN", "FINANCE_OFFICER"))
            // /api/notifications → any logged-in user (not listed = just needs auth)
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path   = request.getURI().getPath();
        String method = request.getMethod().name();

        // CORS preflight always passes
        if ("OPTIONS".equalsIgnoreCase(method)) {
            return chain.filter(exchange);
        }

        // Public paths — no token
        if (isOpen(path)) {
            return chain.filter(exchange);
        }

        // All other paths require a valid token
        String header = request.getHeaders().getFirst("Authorization");
        if (header == null || !header.startsWith("Bearer ")) {
            return deny(exchange, HttpStatus.UNAUTHORIZED);
        }

        String token = header.substring(7);
        if (!jwtUtil.isValid(token)) {
            return deny(exchange, HttpStatus.UNAUTHORIZED);
        }

        String email = jwtUtil.extractEmail(token);
        String role  = jwtUtil.extractRole(token);

        // Role check — ADMIN bypasses all, others checked against the path
        if (!"ADMIN".equals(role) && !roleAllowed(path, role)) {
            return deny(exchange, HttpStatus.FORBIDDEN);
        }

        // Forward identity to the downstream service
        ServerHttpRequest mutated = request.mutate()
                .header("X-User-Email", email)
                .header("X-User-Role", role)
                .build();

        return chain.filter(exchange.mutate().request(mutated).build());
    }

    private boolean isOpen(String path) {
        return OPEN_PATHS.stream().anyMatch(path::startsWith);
    }

    private boolean roleAllowed(String path, String role) {
        // /api/users/me is allowed for any logged-in user
        if (path.startsWith("/api/users/me")) return true;

        // Find the matching path rule
        for (Map.Entry<String, List<String>> entry : PATH_ROLES.entrySet()) {
            if (path.startsWith(entry.getKey())) {
                return entry.getValue().contains(role);
            }
        }
        // Path not in the map (e.g. /api/notifications) → any logged-in user allowed
        return true;
    }

    private Mono<Void> deny(ServerWebExchange exchange, HttpStatus status) {
        exchange.getResponse().setStatusCode(status);
        return exchange.getResponse().setComplete();
    }

    @Override
    public int getOrder() {
        return -1;   // run before routing
    }
}