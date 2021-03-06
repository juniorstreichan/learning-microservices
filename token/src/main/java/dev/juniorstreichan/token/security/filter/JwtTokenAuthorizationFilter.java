package dev.juniorstreichan.token.security.filter;


import com.nimbusds.jwt.SignedJWT;
import dev.juniorstreichan.core.property.JWTConfig;
import dev.juniorstreichan.token.converter.TokenConverter;
import dev.juniorstreichan.token.security.util.SecurityContextUtil;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class JwtTokenAuthorizationFilter extends OncePerRequestFilter {

    protected final JWTConfig jwtConfig;
    protected final TokenConverter tokenConverter;

    @Override
    @SuppressWarnings("Duplicates")
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final var header = request.getHeader(jwtConfig.getHeader().getName());

        if (header == null || !header.startsWith(jwtConfig.getHeader().getPrefix())) {
            filterChain.doFilter(request, response);
            return;
        }

        final var token = header.replace(jwtConfig.getHeader().getPrefix(), "").trim();
        SecurityContextUtil.setSecurityContext(
            "signed".equalsIgnoreCase(jwtConfig.getType()) ? validate(token) : decryptAndValidating(token)
        );

        filterChain.doFilter(request, response);
    }

    @SneakyThrows
    protected SignedJWT decryptAndValidating(final String encryptedToken) {
        final var signedToken = tokenConverter.decryptToken(encryptedToken);
        tokenConverter.validateTokenSignature(signedToken);

        return SignedJWT.parse(signedToken);
    }

    @SneakyThrows
    protected SignedJWT validate(final String signedToken) {

        tokenConverter.validateTokenSignature(signedToken);

        return SignedJWT.parse(signedToken);
    }
}
