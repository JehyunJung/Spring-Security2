package io.security.corespringsecurity.service.impl;

import io.security.corespringsecurity.domain.entity.RoleHierarchy;
import io.security.corespringsecurity.repository.RoleHierarchyRepository;
import io.security.corespringsecurity.service.RoleHierarchyService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class RoleHierarchyServiceImpl implements RoleHierarchyService {
    private final RoleHierarchyRepository roleHierarchyRepository;

    @Override
    public String findAllHierarchy() {
        List<RoleHierarchy> roleHierarchyList = roleHierarchyRepository.findAll();
        StringBuilder stringBuilder = new StringBuilder();
        for (RoleHierarchy roleHierarchy : roleHierarchyList) {
            if(roleHierarchy.getParentName() == null)
                continue;
            stringBuilder.append(roleHierarchy.getParentName().getChildName());
            stringBuilder.append(" > ");
            stringBuilder.append(roleHierarchy.getChildName());
            stringBuilder.append("\n");
        }

        return stringBuilder.toString();
    }
}
