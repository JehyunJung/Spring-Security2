package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.repository.ResourcesRepository;
import io.security.corespringsecurity.security.common.FormAuthenticationDetailsSource;
import io.security.corespringsecurity.security.filter.CustomAuthorizationFilter;
import io.security.corespringsecurity.security.handler.FormAccessDeniedHandler;
import io.security.corespringsecurity.security.handler.FormAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.FormAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.manager.CustomAuthorizationManager;
import io.security.corespringsecurity.security.provider.FormAuthenticationProvider;
import io.security.corespringsecurity.service.RoleHierarchyService;
import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.SpringAuthorizationEventPublisher;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true)
@RequiredArgsConstructor
@Slf4j
public class SecurityConfig {
    private final AuthenticationConfiguration authenticationConfiguration;
    private final FormAuthenticationDetailsSource formAuthenticationDetailsSource;
    private final FormAuthenticationSuccessHandler formAuthenticationSuccessHandler;
    private final  FormAuthenticationFailureHandler formAuthenticationFailureHandler;

    private final FormAuthenticationProvider formAuthenticationProvider;
    private final ApplicationContext applicationContext;

    private final RoleHierarchyService roleHierarchyService;
    private final ResourcesRepository resourcesRepository;
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
    public RoleHierarchyImpl roleHierarchyImpl() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        return roleHierarchy;
    }

    @Bean
    public SecurityResourceService securityResourceService(){
        return new SecurityResourceService(resourcesRepository, roleHierarchyImpl());
    }

    @Bean
    public CustomAuthorizationManager customAuthorizationManager() throws Exception {
        CustomAuthorizationManager customAuthorizationManager = new CustomAuthorizationManager(securityResourceService());
        customAuthorizationManager.setPermitAlls(Arrays.asList(
                new AntPathRequestMatcher("/"),
                new AntPathRequestMatcher("/user"),
                new AntPathRequestMatcher("/login"),
                new AntPathRequestMatcher("/login_proc"),
                new AntPathRequestMatcher("/denied"),
                new AntPathRequestMatcher("/signIn"),
                new AntPathRequestMatcher("/error")));
        customAuthorizationManager.setDeniedIps(Arrays.asList(
                new IpAddressMatcher("192.168.0.0/16")
                )
        );
        customAuthorizationManager.setAuthenticatedUrls("**");

        return customAuthorizationManager;
    }

    public CustomAuthorizationFilter customAuthorizationFilter() throws Exception {
        CustomAuthorizationFilter authorizationFilter = new CustomAuthorizationFilter(customAuthorizationManager());
        authorizationFilter.setAuthorizationEventPublisher((applicationContext.getBeanNamesForType(AuthorizationEventPublisher.class).length > 0) ? applicationContext.getBean(AuthorizationEventPublisher.class) : new SpringAuthorizationEventPublisher(applicationContext));
        authorizationFilter.setSecurityContextHolderStrategy(SecurityContextHolder.getContextHolderStrategy());
        authorizationFilter.setShouldFilterAllDispatcherTypes(true);
        authorizationFilter.setObserveOncePerRequest(true);
        return authorizationFilter;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests()
                .anyRequest().permitAll();

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
        http.addFilterAfter(customAuthorizationFilter(), AuthorizationFilter.class);

        return http.build();
    }
}
