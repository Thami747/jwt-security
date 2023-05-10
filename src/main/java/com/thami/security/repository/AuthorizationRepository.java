package com.thami.security.repository;

import com.thami.security.model.Auth;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

public interface AuthorizationRepository extends JpaRepository<Auth, Long> {
    Optional<Auth> findByEmail(String email);

    @Transactional
    @Modifying
    @Query("UPDATE Auth a SET a.enabled=true WHERE a.email=?1")
    int enableUser(String email);
}

