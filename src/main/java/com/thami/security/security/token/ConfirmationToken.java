package com.thami.security.security.token;

import com.thami.security.model.Auth;
import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
public class ConfirmationToken {

    @Id
    @GeneratedValue (strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String token;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    private LocalDateTime confirmedAt;

    @ManyToOne
    @JoinColumn(nullable = true,
            name = "auth_id")
    private Auth auth;

    public ConfirmationToken() {
    }

    public ConfirmationToken(String token, LocalDateTime createdAt, LocalDateTime expiresAt, Auth auth) {
        this.token = token;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.auth = auth;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public LocalDateTime getConfirmedAt() {
        return confirmedAt;
    }

    public void setConfirmedAt(LocalDateTime confirmedAt) {
        this.confirmedAt = confirmedAt;
    }

    public Auth getUser() {
        return auth;
    }

    public void setUser(Auth auth) {
        this.auth = auth;
    }
}
