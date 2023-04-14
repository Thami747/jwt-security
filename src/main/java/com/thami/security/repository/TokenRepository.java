package com.thami.security.repository;

import com.thami.security.security.token.JwtToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<JwtToken, Long> {

  @Query(value = """
      select t from JwtToken t inner join User u\s
      on t.user.id = u.id\s
      where u.id = :id and (t.expired = false or t.revoked = false)\s
      """)
  List<JwtToken> findAllValidJwtTokenByUser(Long id);

  Optional<JwtToken> findByJwtToken(String jwtToken);
}
