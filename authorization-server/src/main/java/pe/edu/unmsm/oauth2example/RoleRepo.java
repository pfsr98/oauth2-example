package pe.edu.unmsm.oauth2example;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepo extends JpaRepository<Role, Integer> {
    Optional<Role> findByRole(RoleName roleName);
}
