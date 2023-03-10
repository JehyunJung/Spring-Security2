package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.repository.ResourcesRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class SecurityResourceService {
    private final ResourcesRepository resourcesRepository;

    private final RoleHierarchyImpl roleHierarchyImpl;

    List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> securityResources=new ArrayList<>();

    public void load() {
        securityResources.clear();

        List<Resources> allResources = resourcesRepository.findAllResources();

        allResources.forEach(
                (resource)->{
                    Set < String > authoritites = new HashSet<>();
                    resource.getRoleSet().forEach(
                            (role) -> {
                                authoritites.add(role.getRoleName());
                            });
                    AuthorityAuthorizationManager<RequestAuthorizationContext> authorizationManager = AuthorityAuthorizationManager.hasAnyAuthority(authoritites.toArray(new String[0]));
                    authorizationManager.setRoleHierarchy(roleHierarchyImpl);
                    securityResources.add(new RequestMatcherEntry<>(new AntPathRequestMatcher(resource.getResourceName()),authorizationManager));
                }
        );
    }
    public List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> getResourceList() {
        return securityResources;
    }

}
