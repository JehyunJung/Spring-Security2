package io.security.corespringsecurity.domain;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class AccountDto {
    private String username;
    private String password;
    private String email;
    private int age;
    private String role;

    public AccountDto(String username, String password) {
        this.username = username;
        this.password = password;
    }

    public AccountDto(String username, String password, String email, int age, String role) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.age = age;
        this.role = role;
    }
}
