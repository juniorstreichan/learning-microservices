package dev.juniorstreichan.auth.security.config;

import dev.juniorstreichan.auth.security.filter.JWTAuthenticationFilter;
import dev.juniorstreichan.core.property.JWTConfig;
import dev.juniorstreichan.token.converter.TokenConverter;
import dev.juniorstreichan.token.creator.TokenCreator;
import dev.juniorstreichan.token.security.config.SecurityTokenConfig;
import dev.juniorstreichan.token.security.filter.JwtTokenAuthorizationFilter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
public class SecurityCredentialsConfig extends SecurityTokenConfig {

    private final UserDetailsService userDetailsService;
    private final TokenCreator tokenCreator;
    private final TokenConverter tokenConverter;

    public SecurityCredentialsConfig(
        JWTConfig jwtConfig,
        @Qualifier("appUserDetailService") UserDetailsService userDetailsService,
        TokenCreator tokenCreator,
        TokenConverter tokenConverter) {
        super(jwtConfig);

        this.userDetailsService = userDetailsService;
        this.tokenCreator = tokenCreator;
        this.tokenConverter = tokenConverter;
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .addFilter(new JWTAuthenticationFilter(authenticationManager(), jwtConfig, tokenCreator))
                .addFilterAfter(
                    new JwtTokenAuthorizationFilter(jwtConfig,tokenConverter),
                    UsernamePasswordAuthenticationFilter.class
                );

        super.configure(http);

    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
