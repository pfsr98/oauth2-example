package pe.edu.unmsm.oauth2example;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@RequiredArgsConstructor
public class AuthorizationServerApplication implements CommandLineRunner {
    private final RoleRepo roleRepo;

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        Role adminRole = Role.builder().role(RoleName.ROLE_ADMIN).build();
        Role userRole = Role.builder().role(RoleName.ROLE_USER).build();
        roleRepo.save(adminRole);
        roleRepo.save(userRole);
    }
}