package pe.edu.unmsm.oauth2example;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Slf4j
@Service
@RequiredArgsConstructor
public class AppUserService {
    private final AppUserRepo appUserRepo;
    private final RoleRepo roleRepo;
    private final PasswordEncoder passwordEncoder;

    public MessageDto createUser(CreateAppUserDto dto) {
        AppUser appUser = AppUser.builder()
                .username(dto.username())
                .password(passwordEncoder.encode(dto.password()))
                .build();
        Set<Role> roles = new HashSet<>();
        dto.roles().forEach(r -> {
            Role role = roleRepo.findByRole(RoleName.valueOf(r)).orElseThrow(() -> new RuntimeException("Role not found"));
            roles.add(role);
        });
        appUser.setRoles(roles);
        appUserRepo.save(appUser);
        return new MessageDto("User " + appUser.getUsername() + " saved");
    }
}
