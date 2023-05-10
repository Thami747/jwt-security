package com.thami.security.auth;

import com.thami.security.model.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CellphoneRegisterRequest {
    private String firstName;
    private String lastName;
    private String cellphone;
    private String password;
    private String confirmPassword;
    private Role role;
}
