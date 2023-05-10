package com.thami.security.model.request;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateUserRequest {
    private String firstName;
    private String lastName;
    private String email;
    private String cellNumber;
    private String username;
    private String companyName;
    private String companyRegistrationNumber;
    private String vatRegistrationNumber;
    private Integer numberOfEmployees;
    private String password;
    private String confirmPassword;
    private boolean termsAndConditions;
}
