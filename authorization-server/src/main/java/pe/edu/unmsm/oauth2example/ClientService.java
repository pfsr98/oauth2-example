package pe.edu.unmsm.oauth2example;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class ClientService implements RegisteredClientRepository {
    private final ClientRepo clientRepo;
    private final PasswordEncoder passwordEncoder;

    private Client clientFromDto(CreateClientDto dto) {
        return Client.builder()
                .clientId(dto.getClientId())
                .clientSecret(passwordEncoder.encode(dto.getClientSecret()))
                .authenticationMethods(dto.getAuthenticationMethods())
                .authorizationGrantTypes(dto.getAuthorizationGrantTypes())
                .redirectUris(dto.getRedirectUris())
                .scopes(dto.getScopes())
                .requireProofKey(dto.isRequireProofKey())
                .build();
    }

    public MessageDto create(CreateClientDto dto) {
        Client client = clientFromDto(dto);
        clientRepo.save(client);
        return new MessageDto("client " + client.getClientId() + " saved");
    }

    @Override
    public void save(RegisteredClient registeredClient) {

    }

    @Override
    public RegisteredClient findById(String id) {
        Client client = clientRepo.findByClientId(id).orElseThrow(() -> new RuntimeException("Client not found"));
        return Client.toRegisteredClient(client);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        Client client = clientRepo.findByClientId(clientId).orElseThrow(() -> new RuntimeException("Client not found"));
        return Client.toRegisteredClient(client);
    }
}
