package dev.juniorstreichan.token.converter;

import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import dev.juniorstreichan.core.property.JWTConfig;
import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class TokenConverter {
    private final JWTConfig jwtConfig;

    @SneakyThrows
    public String decryptToken(final String encryptedToken) {
        log.info("Decrypting token");

        final var jweObject = JWEObject.parse(encryptedToken);
        final var directDecrypter = new DirectDecrypter(jwtConfig.getPrivateKey().getBytes());

        jweObject.decrypt(directDecrypter);

        log.info("Token decrypted, returning signed token . . . ");

        return jweObject.getPayload().toSignedJWT().serialize();
    }

    @SneakyThrows
    public void validateTokenSignature(final String signedToken) {
        log.info("Starting method to validate token signature . . . ");

        final var signedJWT = SignedJWT.parse(signedToken);

        log.info("Token parsed ! Retrieving public key from signed token");

        final var publicKey = RSAKey.parse(signedJWT.getHeader().getJWK().toJSONObject());

        log.info("Public key retrieved, validating signature . . . ");

        if (!signedJWT.verify(new RSASSAVerifier(publicKey)))
            throw new AccessDeniedException("Invalid token signature!");

        log.info("The token has valid signature");
    }

}
