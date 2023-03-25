package io.security.corespringsecurity.security.init;

import io.security.corespringsecurity.service.RoleHierarchyService;
import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class SecurityInitializer implements ApplicationRunner {
    private final RoleHierarchyService roleHierarchyService;
    private final RoleHierarchyImpl roleHierarchyImpl;
    private final SecurityResourceService securityResourceService;
    @Override
    public void run(ApplicationArguments args) throws Exception {
        securityResourceService.loadUrlResources();
        roleHierarchyImpl.setHierarchy(roleHierarchyService.findAllHierarchy());
    }
}
