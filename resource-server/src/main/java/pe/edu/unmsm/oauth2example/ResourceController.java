package pe.edu.unmsm.oauth2example;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/resource")
public class ResourceController {
    @GetMapping("/user")
    public ResponseEntity<MessageDto> user(Authentication authentication) {
        return ResponseEntity.ok(new MessageDto("Hello " + authentication.getName()));
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping("/admin")
    public ResponseEntity<MessageDto> admin(Authentication authentication) {
        return ResponseEntity.ok(new MessageDto("Hello Mr. " + authentication.getName()));
    }
}
