package com.thami.security.repository;

import com.thami.security.model.Corporate;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface CorporateRepository extends JpaRepository<Corporate, Long> {
    Optional<Corporate> findByEmail(String email);
}

