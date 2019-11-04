package dev.juniorstreichan.core.property;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt.config")
@Getter
@Setter
@ToString
public class JWTConfig {
    private String loginURL = "/login/**";
    @NestedConfigurationProperty
    private Header header = new Header();
    private int expiration = 3600;
    private String privateKey = "tv9vCQdJqWB9entZICeWaUjFuqi5HM9S";
    private String type = "encrypted";

    @Getter
    public static class Header {
        private String name = "Authorization";
        private String prefix = "Bearer ";
    }
}