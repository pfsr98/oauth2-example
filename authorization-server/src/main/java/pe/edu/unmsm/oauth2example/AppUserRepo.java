package pe.edu.unmsm.oauth2example;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AppUserRepo extends JpaRepository<AppUser, Integer> {
    Optional<AppUser> findByUsername(String username);
}
