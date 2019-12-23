package dev.juniorstreichan.security.util;


import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.SignedJWT;
import dev.juniorstreichan.core.model.AppUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class SecurityContextUtil {

    private SecurityContextUtil() {
    }

    public static void setSecurityContext(SignedJWT signedJWT) {
        try {
            final var claims = signedJWT.getJWTClaimsSet();
            final var username = claims.getSubject();

            if (username == null)
                throw new JOSEException("Username missing from JWT");

            final var authorities = claims.getStringListClaim("authorities");

            var appUser = AppUser
                .builder()
                .id(claims.getLongClaim("userId"))
                .username(username)
                .role(String.join(",", authorities))
                .build();

            var auth = new UsernamePasswordAuthenticationToken(
                appUser,
                null,
                createAuthorities(authorities)
            );
            auth.setDetails(signedJWT.serialize());

            SecurityContextHolder.getContext().setAuthentication(auth);

        } catch (Exception e) {
            log.error("Error setting security context", e);
            SecurityContextHolder.clearContext();
        }
    }

    private static List<SimpleGrantedAuthority> createAuthorities(List<String> authorities) {
        return authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
    }
}
