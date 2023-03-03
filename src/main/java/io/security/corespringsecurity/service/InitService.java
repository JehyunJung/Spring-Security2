package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.entity.Role;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class InitService {
    private final UserService userService;

    private final RoleService roleService;



    @PostConstruct
    @Transactional
   void init() {
        /*List<Account> accounts = new ArrayList<>();

        accounts.add(new Account("user","1111","user@email.com",20,new HashSet<>(Arrays.asList(Role.))));
        accounts.add(new Account("manager","1111","manager@email.com",25,"ROLE_MANAGER"));
        accounts.add(new Account("admin","1111","admin@email.com",34,"ROLE_ADMIN"));

        for(AccountDto accountDto: accountDtos){
            userService.createUser(accountDto);
        }*/
        Role role = new Role();
        role.setRoleName("ROLE_USER");
        role.setRoleDesc("유저");
        roleService.createRole(role);
    }
}
