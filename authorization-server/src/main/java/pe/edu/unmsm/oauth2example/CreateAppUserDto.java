package pe.edu.unmsm.oauth2example;

import java.util.List;

public record CreateAppUserDto(
        String username,
        String password,
        List<String> roles
) {
}

