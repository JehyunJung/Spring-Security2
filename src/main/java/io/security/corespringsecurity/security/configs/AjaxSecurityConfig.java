package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.aspectj.weaver.loadtime.Aj;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;

import java.security.Provider;

@Configuration
@RequiredArgsConstructor
public class AjaxSecurityConfig {
    private final AuthenticationConfiguration authenticationConfiguration;
    private final AjaxAuthenticationProvider ajaxAuthenticationProvider;

    @Bean
    public AuthenticationManager ajaxAuthenticationManager(AuthenticationConfiguration authConfiguration) throws Exception {
        ProviderManager authenticationManager = (ProviderManager)authConfiguration.getAuthenticationManager();
        authenticationManager.getProviders().add(0,ajaxAuthenticationProvider);
        return authenticationManager;
    }

    @Bean
    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
        ajaxLoginProcessingFilter.setAuthenticationManager(ajaxAuthenticationManager(authenticationConfiguration));
        return ajaxLoginProcessingFilter;
    }

    @Bean
    @Order(0)
    public SecurityFilterChain ajaxSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity
                .securityMatcher("/api/**")
                .authorizeHttpRequests()
                .anyRequest().authenticated();
        httpSecurity
                .addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

        httpSecurity
                .csrf().disable();

        return httpSecurity.build();
    }
}
