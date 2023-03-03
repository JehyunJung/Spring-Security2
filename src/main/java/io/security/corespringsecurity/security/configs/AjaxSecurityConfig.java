package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.common.AjaxLoginAuthenticationEntryPoint;
import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.corespringsecurity.security.handler.AjaxAccessDeniedHandler;
import io.security.corespringsecurity.security.handler.AjaxFailureHandler;
import io.security.corespringsecurity.security.handler.AjaxSuccessHandler;
import io.security.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

@Configuration
@RequiredArgsConstructor
public class AjaxSecurityConfig {
    private final AuthenticationConfiguration authenticationConfiguration;
    private final AjaxAuthenticationProvider ajaxAuthenticationProvider;

    private final AjaxSuccessHandler ajaxSuccessHandler;
    private final AjaxFailureHandler ajaxFailureHandler;

    private final AjaxLoginAuthenticationEntryPoint ajaxLoginAuthenticationEntryPoint;
    private final AjaxAccessDeniedHandler ajaxAccessDeniedHandler;

    @Bean
    public AuthenticationManager ajaxAuthenticationManager(AuthenticationConfiguration authConfiguration) throws Exception {
        ProviderManager authenticationManager = (ProviderManager)authConfiguration.getAuthenticationManager();
        authenticationManager.getProviders().add(0,ajaxAuthenticationProvider);
        return authenticationManager;
    }


    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter() throws Exception {
        AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
        ajaxLoginProcessingFilter.setAuthenticationManager(ajaxAuthenticationManager(authenticationConfiguration));
        ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxSuccessHandler);
        ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxFailureHandler);
        ajaxLoginProcessingFilter.setSecurityContextRepository(new HttpSessionSecurityContextRepository());
        return ajaxLoginProcessingFilter;
    }

    private void customConfigurerAjax(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .apply(new AjaxLoginConfigurer<>())
                .successHandlerAjax(ajaxSuccessHandler)
                .failureHandlerAjax(ajaxFailureHandler)
                .setAuthenticationManager(ajaxAuthenticationManager(authenticationConfiguration));
        httpSecurity.formLogin()
                .loginPage("/api/login")
                .loginProcessingUrl("api/login")
                .permitAll();
    }

    @Bean
    @Order(0)
    public SecurityFilterChain ajaxSecurityFilterChain(HttpSecurity httpSecurity) throws Exception{
        httpSecurity
                .securityMatcher("/api/**")
                .authorizeHttpRequests()
                .requestMatchers("/api/login").permitAll()
                .requestMatchers("/api/messages").hasRole("MANAGER")

                .anyRequest().authenticated();

        httpSecurity
                .addFilterBefore(ajaxLoginProcessingFilter(), UsernamePasswordAuthenticationFilter.class);

        httpSecurity.formLogin()
                .loginPage("/api/login")
                .loginProcessingUrl("api/login")
                .permitAll();

        //customConfigurerAjax(httpSecurity);

        httpSecurity.exceptionHandling()
                .authenticationEntryPoint(ajaxLoginAuthenticationEntryPoint)
                .accessDeniedHandler(ajaxAccessDeniedHandler);

        return httpSecurity.build();
    }
}
