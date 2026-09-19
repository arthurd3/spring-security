package com.arthur.security.xpath;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class XpathLoginController {

    private final XpathLoginService loginService;

    public XpathLoginController(XpathLoginService loginService) {
        this.loginService = loginService;
    }

    @GetMapping("/api/xlogin")
    public String login(@RequestParam String user, @RequestParam String pass) {
        return loginService.authenticate(user, pass) ? "authenticated" : "denied";
    }
}
