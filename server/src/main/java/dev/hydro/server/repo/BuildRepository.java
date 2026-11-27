package dev.hydro.server.repo;

import dev.hydro.server.model.BuildRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface BuildRepository extends JpaRepository<BuildRecord, Long> {
    Optional<BuildRecord> findByProductIdAndBuildId(String productId, String buildId);
}
