package dev.juniorstreichan.auth.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.juniorstreichan.core.model.AppUser;
import dev.juniorstreichan.core.property.JWTConfig;
import dev.juniorstreichan.token.creator.TokenCreator;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

@RequiredArgsConstructor(onConstructor = @__(@Autowired))
@Slf4j
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;
    private final JWTConfig jwtConfig;
    private final TokenCreator tokenCreator;

    @Override
    @SneakyThrows
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        log.info("Attempting authentication . . .");
        var appUser = new ObjectMapper().readValue(request.getInputStream(), AppUser.class);
        if (appUser == null)
            throw new UsernameNotFoundException("Unable to retrieve the username or password");

        log.info(
                "Creating the authentication object for the user '{}' and calling loadByUsername",
                appUser.getUsername()
        );

        var authenticationToken = new UsernamePasswordAuthenticationToken(
                appUser.getUsername(), appUser.getPassword(), Collections.emptyList()
        );
        authenticationToken.setDetails(appUser);

        return authenticationManager.authenticate(authenticationToken);
    }

    @Override
    @SneakyThrows
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication auth
    ) throws IOException, ServletException {
        log.info("Authentication success for the user '{}', generating JWE token", auth.getName());
        var signedJWT = tokenCreator.createSignedJWT(auth);
        var encryptToken = tokenCreator.encryptToken(signedJWT);
//        var encryptToken = signedJWT.serialize();
        log.info("Token generated successfully, adding it to the response header");
        response.addHeader("Access-Control-Expose-Headers", "XSRF-TOKEN, " + jwtConfig.getHeader().getName());
        response.addHeader(jwtConfig.getHeader().getName(), jwtConfig.getHeader().getPrefix() + encryptToken);
    }

}
