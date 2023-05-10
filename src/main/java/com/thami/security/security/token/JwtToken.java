package com.thami.security.security.token;

import com.thami.security.model.Auth;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
public class JwtToken {
  @Id
  @GeneratedValue
  public Long id;

  @Column(unique = true)
  public String jwtToken;

  @Enumerated(EnumType.STRING)
  public TokenType tokenType = TokenType.BEARER;

  public boolean revoked;

  public boolean expired;

  @ManyToOne
  @JoinColumn(name = "auth_id")
  public Auth auth;
}
