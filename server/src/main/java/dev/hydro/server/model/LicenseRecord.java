package dev.hydro.server.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "hydro_licenses")
public class LicenseRecord {

    @Id
    @Column(nullable = false, length = 128)
    private String licenseKey;

    @Column(nullable = false, length = 128)
    private String productId;

    @Column(nullable = false)
    private boolean active = true;

    @Column(nullable = false)
    private int maxHwids = 1;

    @Column(nullable = false)
    private int maxConcurrentSessions = 1;

    @Column(nullable = false)
    private Instant expiresAt;

    @Column(nullable = false, length = 4096)
    private String boundHwidsCsv = "";

    @Column(length = 256)
    private String note;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    public String getLicenseKey() { return licenseKey; }
    public void setLicenseKey(String licenseKey) { this.licenseKey = licenseKey; }
    public String getProductId() { return productId; }
    public void setProductId(String productId) { this.productId = productId; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
    public int getMaxHwids() { return maxHwids; }
    public void setMaxHwids(int maxHwids) { this.maxHwids = maxHwids; }
    public int getMaxConcurrentSessions() { return maxConcurrentSessions; }
    public void setMaxConcurrentSessions(int maxConcurrentSessions) { this.maxConcurrentSessions = maxConcurrentSessions; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    public String getBoundHwidsCsv() { return boundHwidsCsv; }
    public void setBoundHwidsCsv(String boundHwidsCsv) { this.boundHwidsCsv = boundHwidsCsv; }
    public String getNote() { return note; }
    public void setNote(String note) { this.note = note; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
