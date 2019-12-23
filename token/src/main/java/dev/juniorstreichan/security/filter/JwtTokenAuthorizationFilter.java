package dev.juniorstreichan.security.filter;


import com.nimbusds.jwt.SignedJWT;
import dev.juniorstreichan.core.property.JWTConfig;
import dev.juniorstreichan.security.util.SecurityContextUtil;
import dev.juniorstreichan.token.converter.TokenConverter;
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

    private final JWTConfig jwtConfig;
    private final TokenConverter tokenConverter;

    @Override
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
    private SignedJWT decryptAndValidating(final String encryptedToken) {
        final var signedToken = tokenConverter.decryptToken(encryptedToken);
        tokenConverter.validateTokenSignature(signedToken);

        return SignedJWT.parse(signedToken);
    }

    @SneakyThrows
    private SignedJWT validate(final String signedToken) {

        tokenConverter.validateTokenSignature(signedToken);

        return SignedJWT.parse(signedToken);
    }
}
