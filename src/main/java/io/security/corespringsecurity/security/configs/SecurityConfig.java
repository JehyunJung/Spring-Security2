package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.common.FormAuthenticationDetailsSource;
import io.security.corespringsecurity.security.handler.FormAccessDeniedHandler;
import io.security.corespringsecurity.security.handler.FormAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.FormAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.provider.FormAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {
    private final AuthenticationConfiguration authenticationConfiguration;
    private final FormAuthenticationDetailsSource formAuthenticationDetailsSource;
    private final FormAuthenticationSuccessHandler formAuthenticationSuccessHandler;
    private final  FormAuthenticationFailureHandler formAuthenticationFailureHandler;

    private final FormAuthenticationProvider formAuthenticationProvider;


    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) ->
                web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public AuthenticationManager formAuthenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        ProviderManager providerManager = (ProviderManager)authenticationConfiguration.getAuthenticationManager();
        providerManager.getProviders().add(0, formAuthenticationProvider);
        return providerManager;
    }

    @Bean
    public FormAccessDeniedHandler formAccessDeniedHandler() {
        FormAccessDeniedHandler formAccessDeniedHandler = new FormAccessDeniedHandler();
        formAccessDeniedHandler.setErrorPage("/denied");
        return formAccessDeniedHandler;
    }
    
    @Bean
    @Order(1)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests()
                .requestMatchers("/mypage").hasRole("USER")
                .requestMatchers("/messages").hasRole("MANAGER")
                .requestMatchers("/config").hasRole("ADMIN")
                .requestMatchers("/**").permitAll()
                .anyRequest().authenticated();

        http
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc")
                .authenticationDetailsSource(formAuthenticationDetailsSource)
                .successHandler(formAuthenticationSuccessHandler)
                .failureHandler(formAuthenticationFailureHandler)
                .permitAll();

        http
                .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
                .accessDeniedPage("/denied")
                .accessDeniedHandler(formAccessDeniedHandler());


        http
                .csrf().disable();

        return http.build();
    }
}
