package dev.juniorstreichan.gateway.security.config;


import dev.juniorstreichan.core.property.JWTConfig;
import dev.juniorstreichan.gateway.security.filter.GatewayJwtAuthorizationFilter;
import dev.juniorstreichan.token.converter.TokenConverter;
import dev.juniorstreichan.token.security.config.SecurityTokenConfig;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityConfig extends SecurityTokenConfig {
    private final TokenConverter tokenConverter;

    public SecurityConfig(JWTConfig jwtConfig, TokenConverter tokenConverter) {
        super(jwtConfig);
        this.tokenConverter = tokenConverter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterAfter(
            new GatewayJwtAuthorizationFilter(jwtConfig, tokenConverter),
            UsernamePasswordAuthenticationFilter.class
        );
        super.configure(http);
    }
}
