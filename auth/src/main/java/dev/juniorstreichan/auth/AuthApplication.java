package dev.juniorstreichan.auth;

import dev.juniorstreichan.core.property.JWTConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication
@EntityScan({"dev.juniorstreichan.core.model"})
@EnableJpaRepositories({"dev.juniorstreichan.core.repository"})
@EnableConfigurationProperties(value = JWTConfig.class)
@ComponentScan("dev.juniorstreichan")
@EnableEurekaClient
public class AuthApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthApplication.class, args);
    }

}
