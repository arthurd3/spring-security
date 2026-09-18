package com.arthur.security.login;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

/**
 * Bridges Spring Security's authentication events to the {@link LoginAttemptService}.
 *
 * <p>Spring Boot auto-configures a {@code DefaultAuthenticationEventPublisher}, so every
 * {@code DaoAuthenticationProvider} outcome is published as an application event. A bad password fires
 * {@link AuthenticationFailureBadCredentialsEvent}; a locked account fires a <i>different</i> event, so
 * the failure counter is not inflated once an account is already locked.
 */
@Component
public class AuthenticationEventListener {

    private final LoginAttemptService loginAttemptService;

    public AuthenticationEventListener(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    @EventListener
    public void onFailure(AuthenticationFailureBadCredentialsEvent event) {
        loginAttemptService.loginFailed(event.getAuthentication().getName());
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        loginAttemptService.loginSucceeded(event.getAuthentication().getName());
    }
}
