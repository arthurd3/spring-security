package com.arthur.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class MainController {

    @GetMapping("/welcome")
    public String welcome() {
        return "<h1>Welcome!</h1>";
    }

    @GetMapping("/user")
    public String user() {
        return "<h1>User!</h1>";
    }

    @GetMapping("/admin")
    public String admin() {
        return "<h1>Admin!</h1>";
    }
}
