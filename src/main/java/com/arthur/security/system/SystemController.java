package com.arthur.security.system;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Hardened counterpart to the {@code /vulnerable/ping} lab endpoint. All the safety is in
 * {@link CommandService#ping(String)}.
 */
@RestController
@RequestMapping("/api/system")
public class SystemController {

    private final CommandService commandService;

    public SystemController(CommandService commandService) {
        this.commandService = commandService;
    }

    @GetMapping("/ping")
    public String ping(@RequestParam String host) {
        return commandService.ping(host);
    }
}
