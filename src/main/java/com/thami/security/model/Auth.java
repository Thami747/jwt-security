package com.thami.security.model;

import com.thami.security.security.token.JwtToken;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
@Entity
@Table(name = "auth")
public class Auth implements UserDetails {
    @Id
    @GeneratedValue
    private Long id;
    private String email;
    private String cellNumber;
    private String username;
    private String password;
    @Enumerated(EnumType.STRING)
    private Role role;

    @OneToMany(mappedBy = "auth")
    private List<JwtToken> jwtTokens;

    private Boolean locked;
    private Boolean enabled;
    private Boolean accountNonExpired;
    private Boolean credentialsNonExpired;
    @ManyToOne
    @JoinColumn(nullable = true,
            name = "individual_id")
    private Individual individual;
    @ManyToOne
    @JoinColumn(nullable = true,
            name = "corporate_id")
    private Corporate corporate;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    public Auth(String email, String password, Role role) {
        this.email = email;
        this.password = password;
        this.username = email;
        this.role = role;
        this.locked = false;
        this.enabled = false;
        this.accountNonExpired = false;
        this.credentialsNonExpired = false;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return !this.accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !this.locked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return !this.credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }
}
