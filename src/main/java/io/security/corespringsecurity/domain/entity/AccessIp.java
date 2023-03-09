package io.security.corespringsecurity.domain.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "ACCESS_IP")
@Data
@EqualsAndHashCode(of="id")
@NoArgsConstructor
@AllArgsConstructor
public class AccessIp {
    @Id
    @GeneratedValue
    @Column(name="IP_ID")
    private Long id;

    @Column(name="IP_ADDRESS",nullable = false)
    private String ipAddress;
}
