package com.example.authservice.repository;

import com.example.authservice.entity.RefreshSessions;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.UUID;
import java.util.Optional;

@Repository
public interface RefreshSessionsRepository extends JpaRepository<RefreshSessions, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select session from RefreshSessions session where session.uuid = :id")
    Optional<RefreshSessions> findByIdForUpdate(@Param("id") UUID id);
}
