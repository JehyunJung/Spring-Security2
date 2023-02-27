package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.domain.AccountDto;

public interface UserService {
    void createUser(AccountDto accountDto);
}
