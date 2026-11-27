package dev.hydro.server.model;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "hydro_builds", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"productId", "buildId"})
})
public class BuildRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 128)
    private String productId;

    @Column(nullable = false, length = 64)
    private String buildId;

    @Column(nullable = false, length = 32)
    private String jarDigest;

    @Column(nullable = false, length = 32)
    private String symDigest;

    @Column(nullable = false, length = 32)
    private String vmShareHex;

    @Column(nullable = false, length = 32)
    private String vaultShareHex;

    @Column(nullable = false, length = 256)
    private String dynParamsHex;

    @Column(nullable = false)
    private boolean revoked = false;

    @Column(length = 256)
    private String note;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    public Long getId() { return id; }
    public String getProductId() { return productId; }
    public void setProductId(String productId) { this.productId = productId; }
    public String getBuildId() { return buildId; }
    public void setBuildId(String buildId) { this.buildId = buildId; }
    public String getJarDigest() { return jarDigest; }
    public void setJarDigest(String jarDigest) { this.jarDigest = jarDigest; }
    public String getSymDigest() { return symDigest; }
    public void setSymDigest(String symDigest) { this.symDigest = symDigest; }
    public String getVmShareHex() { return vmShareHex; }
    public void setVmShareHex(String vmShareHex) { this.vmShareHex = vmShareHex; }
    public String getVaultShareHex() { return vaultShareHex; }
    public void setVaultShareHex(String vaultShareHex) { this.vaultShareHex = vaultShareHex; }
    public String getDynParamsHex() { return dynParamsHex; }
    public void setDynParamsHex(String dynParamsHex) { this.dynParamsHex = dynParamsHex; }
    public boolean isRevoked() { return revoked; }
    public void setRevoked(boolean revoked) { this.revoked = revoked; }
    public String getNote() { return note; }
    public void setNote(String note) { this.note = note; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
