package dev.juniorstreichan.auth.security.user;

import dev.juniorstreichan.core.repository.AppUserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor(onConstructor = @__(@Autowired))
public class AppUserDetails implements UserDetailsService {
    private final AppUserRepository appUserRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        log.info("Searching user with username '{}'", username);
        var user = appUserRepository.findByUsername(username);

        if (user == null)
            throw new UsernameNotFoundException(String.format("User not found '%s' ", username));
        // PAREI AQUI https://youtu.be/9ae68fV1zZM?list=PL62G310vn6nH_iMQoPMhIlK_ey1npyUUl&t=1178
        return null;
    }
}
