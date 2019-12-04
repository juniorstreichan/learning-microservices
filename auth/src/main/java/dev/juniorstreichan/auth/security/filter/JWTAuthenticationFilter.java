package dev.juniorstreichan.auth.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import dev.juniorstreichan.core.model.AppUser;
import dev.juniorstreichan.core.property.JWTConfig;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

@RequiredArgsConstructor
@Slf4j
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    // PAREI AQUI https://youtu.be/XS9w0SkKrFk?list=PL62G310vn6nH_iMQoPMhIlK_ey1npyUUl&t=2421
    private final AuthenticationManager authenticationManager;
    private final JWTConfig jwtConfig;

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
        var signedJWT = createSignedJWT(auth);
        var encryptToken = encryptToken(signedJWT);
        log.info("Token generated successfully, adding it to the response header");
        response.addHeader("Access-Control-Expose-Headers", "XSRF-TOKEN, " + jwtConfig.getHeader().getName());
        response.addHeader(jwtConfig.getHeader().getName(), jwtConfig.getHeader().getPrefix() + encryptToken);
    }

    @SneakyThrows
    private SignedJWT createSignedJWT(Authentication auth) {
        log.info("Starting to create the signed JWT");
        var appUser = (AppUser) auth.getPrincipal();
        var jwtClaimsSet = createJwtClaimsSet(auth, appUser);
        var rsaKeys = generateKeyPair();

        log.info("Building JWK from the RSA Keys");

        var jwk = new RSAKey.Builder((RSAPublicKey) rsaKeys.getPublic()).keyID(UUID.randomUUID().toString()).build();

        var signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .jwk(jwk)
                        .type(JOSEObjectType.JWT)
                        .build(),
                jwtClaimsSet
        );

        log.info("Signing the token with the private RSA Key");

        var signer = new RSASSASigner(rsaKeys.getPrivate());

        signedJWT.sign(signer);
        log.info("Serialized token '{}'", signedJWT.serialize());

        return signedJWT;
    }

    private JWTClaimsSet createJwtClaimsSet(Authentication auth, AppUser appUser) {
        log.info("Creating JWTClaimSet Object for '{}' ", appUser);
        return new JWTClaimsSet.Builder().subject(appUser.getUsername())
                .claim(
                        "authorities",
                        auth.getAuthorities()
                                .stream().map(GrantedAuthority::getAuthority)
                                .collect(Collectors.toList())

                )
                .issuer("http://juniorstreichan.dev")
                .issueTime(new Date())
                .expirationTime(new Date(System.currentTimeMillis() + (jwtConfig.getExpiration() * 1000)))
                .build();

    }

    @SneakyThrows
    private KeyPair generateKeyPair() {
        log.info("Generating RSA 2048 bits Keys");
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        return generator.genKeyPair();
    }

    private String encryptToken(SignedJWT signedJWT) throws JOSEException {
        log.info("Starting the encrypt token method");
        var encrypter = new DirectEncrypter(jwtConfig.getPrivateKey().getBytes());

        var jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256)
                        .contentType("JWT")
                        .build(),
                new Payload(signedJWT)
        );
        log.info("Encrypting token with system's private key");

        jweObject.encrypt(encrypter);

        log.info("Token encrypted");

        return jweObject.serialize();
    }
}
