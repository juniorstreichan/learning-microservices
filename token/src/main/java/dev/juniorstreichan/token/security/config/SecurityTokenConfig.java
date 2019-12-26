package dev.juniorstreichan.token.security.config;

import dev.juniorstreichan.core.property.JWTConfig;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.cors.CorsConfiguration;

import javax.servlet.http.HttpServletResponse;


@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class SecurityTokenConfig extends WebSecurityConfigurerAdapter {

    protected final JWTConfig jwtConfig;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .cors().configurationSource(req -> new CorsConfiguration().applyPermitDefaultValues())
            .and()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .exceptionHandling().authenticationEntryPoint((req, res, ex) -> {
            System.out.println(ex.getLocalizedMessage());
            res.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        })
            .and()
            .authorizeRequests()
            .antMatchers(jwtConfig.getLoginURL()).permitAll()
            .antMatchers("/course/v1/admin/**").hasRole("ADMIN")
            .antMatchers("/auth/user/**").hasAnyRole("ADMIN", "USER")
            .anyRequest().authenticated();

    }

}
