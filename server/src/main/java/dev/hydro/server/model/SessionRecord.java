package dev.hydro.server.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "hydro_sessions")
public class SessionRecord {

    @Id
    @Column(nullable = false, length = 64)
    private String sessionId;

    @Column(nullable = false, length = 128)
    private String licenseKey;

    @Column(nullable = false, length = 128)
    private String productId;

    @Column(nullable = false, length = 64)
    private String buildId;

    @Column(nullable = false, length = 64)
    private String hwid;

    @Column(nullable = false, length = 64)
    private String masterSessionKeyHex;

    @Column(nullable = false, length = 64)
    private String encKeyHex;

    @Column(nullable = false, length = 64)
    private String macKeyHex;

    @Column(nullable = false, length = 64)
    private String rollingKeyHex;

    @Column(nullable = false, length = 32)
    private String sessionGuardHex = "";

    @Column(nullable = false, length = 64)
    private String clientPubHex;

    @Column(nullable = false)
    private long seq = 0;

    @Column(nullable = false)
    private boolean active = true;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant lastHeartbeatAt = Instant.now();

    @Column(nullable = false)
    private Instant expiresAt;

    @Column(length = 64)
    private String clientIp;

    public String getSessionId() { return sessionId; }
    public void setSessionId(String sessionId) { this.sessionId = sessionId; }
    public String getLicenseKey() { return licenseKey; }
    public void setLicenseKey(String licenseKey) { this.licenseKey = licenseKey; }
    public String getProductId() { return productId; }
    public void setProductId(String productId) { this.productId = productId; }
    public String getBuildId() { return buildId; }
    public void setBuildId(String buildId) { this.buildId = buildId; }
    public String getHwid() { return hwid; }
    public void setHwid(String hwid) { this.hwid = hwid; }
    public String getMasterSessionKeyHex() { return masterSessionKeyHex; }
    public void setMasterSessionKeyHex(String masterSessionKeyHex) { this.masterSessionKeyHex = masterSessionKeyHex; }
    public String getEncKeyHex() { return encKeyHex; }
    public void setEncKeyHex(String encKeyHex) { this.encKeyHex = encKeyHex; }
    public String getMacKeyHex() { return macKeyHex; }
    public void setMacKeyHex(String macKeyHex) { this.macKeyHex = macKeyHex; }
    public String getRollingKeyHex() { return rollingKeyHex; }
    public void setRollingKeyHex(String rollingKeyHex) { this.rollingKeyHex = rollingKeyHex; }
    public String getSessionGuardHex() { return sessionGuardHex; }
    public void setSessionGuardHex(String sessionGuardHex) { this.sessionGuardHex = sessionGuardHex; }
    public String getClientPubHex() { return clientPubHex; }
    public void setClientPubHex(String clientPubHex) { this.clientPubHex = clientPubHex; }
    public long getSeq() { return seq; }
    public void setSeq(long seq) { this.seq = seq; }
    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
    public Instant getLastHeartbeatAt() { return lastHeartbeatAt; }
    public void setLastHeartbeatAt(Instant lastHeartbeatAt) { this.lastHeartbeatAt = lastHeartbeatAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public void setExpiresAt(Instant expiresAt) { this.expiresAt = expiresAt; }
    public String getClientIp() { return clientIp; }
    public void setClientIp(String clientIp) { this.clientIp = clientIp; }
}
