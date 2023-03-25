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

import java.util.*;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class SecurityResourceService {
    private final ResourcesRepository resourcesRepository;

    private final RoleHierarchyImpl roleHierarchyImpl;

    List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> urlResources=new ArrayList<>();
    LinkedHashMap<String,List<String>> methodResources=new LinkedHashMap<>();

    public void loadUrlResources() {
        urlResources.clear();

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
                    urlResources.add(new RequestMatcherEntry<>(new AntPathRequestMatcher(resource.getResourceName()),authorizationManager));
                }
        );
    }
    public List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> getUrlResourceList() {
        return urlResources;
    }

    public void loadMethodResources() {
        methodResources.clear();

        List<Resources> allResources = resourcesRepository.findAllMethodResources();

        allResources.forEach(
                (resource)->{
                    Set < String > authoritites = new HashSet<>();
                    resource.getRoleSet().forEach(
                            (role) -> {
                                authoritites.add(role.getRoleName());
                            });
                    AuthorityAuthorizationManager<RequestAuthorizationContext> authorizationManager = AuthorityAuthorizationManager.hasAnyAuthority(authoritites.toArray(new String[0]));
                    methodResources.put(resource.getResourceName(),new ArrayList<>(authoritites));
                }
        );
    }
    public LinkedHashMap<String, List<String>> getMethodResourceList() {
        return methodResources;
    }





}
