package dev.hydro.server.repo;

import dev.hydro.server.model.LicenseRecord;
import org.springframework.data.jpa.repository.JpaRepository;

public interface LicenseRepository extends JpaRepository<LicenseRecord, String> {
}
