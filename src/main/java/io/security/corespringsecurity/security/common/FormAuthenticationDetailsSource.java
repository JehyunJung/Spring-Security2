package io.security.corespringsecurity.security.common;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.stereotype.Component;

@Component
public class FormAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest, FormWebAuthenticationDetails> {
    @Override
    public FormWebAuthenticationDetails buildDetails(HttpServletRequest context) {
        return new FormWebAuthenticationDetails(context);
    }
}
