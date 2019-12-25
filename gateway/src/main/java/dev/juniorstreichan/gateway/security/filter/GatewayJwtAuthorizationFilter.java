package dev.juniorstreichan.gateway.security.filter;

import dev.juniorstreichan.core.property.JWTConfig;
import dev.juniorstreichan.token.converter.TokenConverter;
import dev.juniorstreichan.token.security.filter.JwtTokenAuthorizationFilter;
import lombok.SneakyThrows;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class GatewayJwtAuthorizationFilter extends JwtTokenAuthorizationFilter {

    public GatewayJwtAuthorizationFilter(JWTConfig jwtConfig, TokenConverter tokenConverter) {
        super(jwtConfig, tokenConverter);
    }

    @Override
    @SneakyThrows
    @SuppressWarnings("duplicates")
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
        final var header = request.getHeader(jwtConfig.getHeader().getName());

        if (header == null || !header.startsWith(jwtConfig.getHeader().getPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }

        final var token = header.replace(jwtConfig.getHeader().getPrefix(), "").trim();
        final var signedToken = tokenConverter.decryptToken(token);
        tokenConverter.validateTokenSignature(signedToken);

        filterChain.doFilter(request, response);
    }
}
