package io.security.corespringsecurity.security.configs;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@Configuration
@EnableMethodSecurity(prePostEnabled = true,securedEnabled = true)
public class MethodSecurityConfig {
}
