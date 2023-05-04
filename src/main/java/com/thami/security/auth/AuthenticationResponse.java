package com.thami.security.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationResponse {
    @JsonProperty("jwt_token")
    private String jwtToken;
    @JsonProperty("confirm_token")
    private String confirmToken;
    @JsonProperty("refresh_token")
    private String refreshToken;
    @JsonProperty("message")
    private String message;
}
