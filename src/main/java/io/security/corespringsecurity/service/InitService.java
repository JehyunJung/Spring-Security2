package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.AccountDto;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class InitService {
    private final UserService userService;

    @PostConstruct
    @Transactional
    void init() {
        List<AccountDto> accountDtos = new ArrayList<>();

        accountDtos.add(new AccountDto("user","1111","user@email.com",20,"ROLE_USER"));
        accountDtos.add(new AccountDto("manager","1111","manager@email.com",25,"ROLE_MANAGER"));
        accountDtos.add(new AccountDto("admin","1111","admin@email.com",34,"ROLE_ADMIN"));

        for(AccountDto accountDto: accountDtos){
            userService.createUser(accountDto);
        }
    }
}
