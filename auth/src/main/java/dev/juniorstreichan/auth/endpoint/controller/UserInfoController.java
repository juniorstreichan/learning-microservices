package dev.juniorstreichan.auth.endpoint.controller;

import dev.juniorstreichan.core.model.AppUser;
import org.springframework.http.HttpEntity;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("user")
public class UserInfoController {

    @GetMapping(path = "info", produces = MediaType.APPLICATION_JSON_VALUE)
    public HttpEntity<AppUser> getUserInfo(Principal principal) {
        var appUser = (AppUser) ((UsernamePasswordAuthenticationToken) principal).getPrincipal();
        return ResponseEntity.ok(appUser);
    }
}
