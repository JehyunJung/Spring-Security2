package io.security.corespringsecurity.domain.entity;

import jakarta.persistence.*;
import lombok.*;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Set;

@Entity
@Data
@ToString(exclude = {"userRoles"})
@Builder
@EqualsAndHashCode(of = "id")
@NoArgsConstructor
@AllArgsConstructor
public class Account implements Serializable {

    @Id
    @GeneratedValue
    private Long id;

    @Column
    private String username;

    @Column
    private String password;

    @Column
    private String email;

    @Column
    private int age;


    public Account(String username, String password, String email, int age, Set<Role> userRoles) {
        this.username = username;
        this.password = password;
        this.email = email;
        this.age = age;
        this.userRoles = userRoles;
    }

    @ManyToMany(fetch = FetchType.LAZY, cascade={CascadeType.ALL})
    @JoinTable(name = "account_roles", joinColumns = { @JoinColumn(name = "account_id") }, inverseJoinColumns = {
            @JoinColumn(name = "role_id") })
    private Set<Role> userRoles = new HashSet<>();
}


