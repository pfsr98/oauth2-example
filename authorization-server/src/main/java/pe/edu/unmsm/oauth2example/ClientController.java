package pe.edu.unmsm.oauth2example;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/client")
@RequiredArgsConstructor
public class ClientController {
    private final ClientService clientService;

    @PostMapping("/create")
    public ResponseEntity<MessageDto> create(@RequestBody CreateClientDto dto) {
        return ResponseEntity.status(HttpStatus.CREATED).body(clientService.create(dto));
    }
}
