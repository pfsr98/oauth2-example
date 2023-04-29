package pe.edu.unmsm.oauth2example;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class CreateClientDto {
    private String clientId;
    private String clientSecret;
    private Set<ClientAuthenticationMethod> authenticationMethods;
    private Set<AuthorizationGrantType> authorizationGrantTypes;
    private Set<String> redirectUris;
    private Set<String> scopes;
    private boolean requireProofKey;
}
