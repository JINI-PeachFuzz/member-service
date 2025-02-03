package org.koreait.member.repositories;

import org.koreait.member.entities.TempToken;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.querydsl.QuerydslPredicateExecutor;

import java.util.Optional;

public interface TempTokenRepository extends JpaRepository<TempToken, String>, QuerydslPredicateExecutor<TempToken> {
    @EntityGraph(attributePaths = "member")
    Optional<TempToken> findByToken(String token); // patch join을 할려고 넣은거
}