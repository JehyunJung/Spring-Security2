package io.security.corespringsecurity.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.Data;

@Data
public class AccountDto {
    private String username;
    private String password;
    private String email;
    private int age;
    private String role;
}
