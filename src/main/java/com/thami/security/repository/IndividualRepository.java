package com.thami.security.repository;

import com.thami.security.model.Individual;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface IndividualRepository extends JpaRepository<Individual, Long> {
    Optional<Individual> findByEmail(String email);
}

