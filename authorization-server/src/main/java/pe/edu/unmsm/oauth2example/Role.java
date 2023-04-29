package pe.edu.unmsm.oauth2example;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

@Builder
@NoArgsConstructor
@AllArgsConstructor
@Data
@Entity
public class Role implements GrantedAuthority {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;

    @Enumerated(EnumType.STRING)
    private RoleName role;

    @Override
    public String getAuthority() {
        return role.name();
    }
}
