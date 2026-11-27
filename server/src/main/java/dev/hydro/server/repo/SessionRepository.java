package dev.hydro.server.repo;

import dev.hydro.server.model.SessionRecord;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.Instant;
import java.util.List;

public interface SessionRepository extends JpaRepository<SessionRecord, String> {
    List<SessionRecord> findByLicenseKeyAndActiveTrueOrderByCreatedAtAsc(String licenseKey);
    List<SessionRecord> findByActiveTrue();
    List<SessionRecord> findByActiveTrueAndExpiresAtBefore(Instant cutoff);
}
