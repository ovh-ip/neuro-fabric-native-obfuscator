package dev.hydro.server.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "hydro_audit")
public class AuditEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Instant occurredAt = Instant.now();

    @Column(nullable = false, length = 64)
    private String eventType;

    @Column(length = 128)
    private String licenseKey;

    @Column(length = 64)
    private String buildId;

    @Column(length = 64)
    private String hwid;

    @Column(length = 64)
    private String ip;

    @Column(length = 512)
    private String details;

    public Long getId() { return id; }
    public Instant getOccurredAt() { return occurredAt; }
    public String getEventType() { return eventType; }
    public void setEventType(String eventType) { this.eventType = eventType; }
    public String getLicenseKey() { return licenseKey; }
    public void setLicenseKey(String licenseKey) { this.licenseKey = licenseKey; }
    public String getBuildId() { return buildId; }
    public void setBuildId(String buildId) { this.buildId = buildId; }
    public String getHwid() { return hwid; }
    public void setHwid(String hwid) { this.hwid = hwid; }
    public String getIp() { return ip; }
    public void setIp(String ip) { this.ip = ip; }
    public String getDetails() { return details; }
    public void setDetails(String details) { this.details = details; }
}
