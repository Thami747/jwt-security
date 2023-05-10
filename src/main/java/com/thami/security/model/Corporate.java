package com.thami.security.model;

import jakarta.persistence.*;
import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "corporate")
public class Corporate {
    @Id
    @GeneratedValue
    private Long id;
    private String email;
    private String cellNumber;
    private String companyName;
    private String companyRegistrationNumber;
    private String vatRegistrationNumber;
    private Integer numberOfEmployees;
    private String password;
    private boolean termsAndConditions;
    @Enumerated(EnumType.STRING)
    private Role role;
}
