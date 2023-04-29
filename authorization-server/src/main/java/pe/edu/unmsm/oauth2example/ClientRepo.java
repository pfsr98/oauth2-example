package pe.edu.unmsm.oauth2example;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ClientRepo extends JpaRepository<Client, Integer> {
    Optional<Client> findByClientId(String clientId);
}
