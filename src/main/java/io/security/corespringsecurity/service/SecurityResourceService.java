package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.repository.ResourcesRepository;
import lombok.RequiredArgsConstructor;
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

    List<RequestMatcherEntry<Set<String>>> securityResources=new ArrayList<>();

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
                    securityResources.add(new RequestMatcherEntry<>(new AntPathRequestMatcher(resource.getResourceName()),authoritites));
                }
        );
    }
    public List<RequestMatcherEntry<Set<String>>> getResourceList() {
        return securityResources;
    }

}
