package dev.hydro.server.controller;

import dev.hydro.server.crypto.HydroCrypto;
import dev.hydro.server.crypto.ServerCryptoService;
import dev.hydro.server.model.AuditEvent;
import dev.hydro.server.model.BuildRecord;
import dev.hydro.server.model.LicenseRecord;
import dev.hydro.server.model.SessionRecord;
import dev.hydro.server.repo.AuditEventRepository;
import dev.hydro.server.repo.BuildRepository;
import dev.hydro.server.repo.LicenseRepository;
import dev.hydro.server.repo.SessionRepository;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@RestController
@RequestMapping("/api/v1/admin")
public class AdminController {

    public record RegisterBuildReq(
            String productId,
            String buildId,
            String jarDigest,
            String symDigest,
            String vmShareHex,
            String vaultShareHex,
            String dynParamsHex,
            String note) {}

    public record CreateLicenseReq(
            String licenseKey,
            String productId,
            Integer durationDays,
            Integer maxHwids,
            Integer maxConcurrentSessions,
            String note) {}

    private final ServerCryptoService cryptoService;
    private final BuildRepository buildRepo;
    private final LicenseRepository licenseRepo;
    private final SessionRepository sessionRepo;
    private final AuditEventRepository auditRepo;

    public AdminController(
            ServerCryptoService cryptoService,
            BuildRepository buildRepo,
            LicenseRepository licenseRepo,
            SessionRepository sessionRepo,
            AuditEventRepository auditRepo) {
        this.cryptoService = cryptoService;
        this.buildRepo = buildRepo;
        this.licenseRepo = licenseRepo;
        this.sessionRepo = sessionRepo;
        this.auditRepo = auditRepo;
    }

    private void checkAdmin(String token) {
        if (!HydroCrypto.constantTimeEquals(token, cryptoService.getAdminToken())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid admin token");
        }
    }

    @PostMapping("/builds")
    @Transactional
    public Map<String, Object> registerBuild(
            @RequestHeader(value = "X-Admin-Token", required = false) String token,
            @RequestBody RegisterBuildReq req) {
        checkAdmin(token);
        BuildRecord rec = buildRepo.findByProductIdAndBuildId(req.productId(), req.buildId())
                .orElseGet(BuildRecord::new);
        rec.setProductId(req.productId());
        rec.setBuildId(req.buildId());
        rec.setJarDigest(req.jarDigest().toLowerCase(Locale.ROOT));
        rec.setSymDigest(req.symDigest().toLowerCase(Locale.ROOT));
        rec.setVmShareHex(req.vmShareHex().toLowerCase(Locale.ROOT));
        rec.setVaultShareHex(req.vaultShareHex().toLowerCase(Locale.ROOT));
        rec.setDynParamsHex(req.dynParamsHex() == null ? "0000000000000000" : req.dynParamsHex().toLowerCase(Locale.ROOT));
        rec.setRevoked(false);
        rec.setNote(req.note());
        buildRepo.save(rec);
        return Map.of("ok", true, "productId", rec.getProductId(), "buildId", rec.getBuildId());
    }

    @PostMapping("/builds/{productId}/{buildId}/revoke")
    @Transactional
    public Map<String, Object> revokeBuild(
            @RequestHeader(value = "X-Admin-Token", required = false) String token,
            @PathVariable String productId,
            @PathVariable String buildId) {
        checkAdmin(token);
        BuildRecord rec = buildRepo.findByProductIdAndBuildId(productId, buildId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        rec.setRevoked(true);
        buildRepo.save(rec);
        return Map.of("ok", true, "revoked", true);
    }

    @PostMapping("/licenses")
    @Transactional
    public LicenseRecord createLicense(
            @RequestHeader(value = "X-Admin-Token", required = false) String token,
            @RequestBody CreateLicenseReq req) {
        checkAdmin(token);
        String key = (req.licenseKey() != null && !req.licenseKey().isBlank())
                ? req.licenseKey()
                : "HY-" + HydroCrypto.toHex(HydroCrypto.randomBytes(12, cryptoService.getRng())).toUpperCase(Locale.ROOT);
        LicenseRecord lic = licenseRepo.findById(key).orElseGet(LicenseRecord::new);
        lic.setLicenseKey(key);
        lic.setProductId(req.productId() == null || req.productId().isBlank() ? "*" : req.productId());
        lic.setActive(true);
        lic.setMaxHwids(req.maxHwids() == null ? 1 : Math.max(1, req.maxHwids()));
        lic.setMaxConcurrentSessions(req.maxConcurrentSessions() == null ? 1 : Math.max(1, req.maxConcurrentSessions()));
        int days = req.durationDays() == null ? 30 : Math.max(1, req.durationDays());
        lic.setExpiresAt(Instant.now().plus(days, ChronoUnit.DAYS));
        if (lic.getBoundHwidsCsv() == null) lic.setBoundHwidsCsv("");
        lic.setNote(req.note());
        return licenseRepo.save(lic);
    }

    @PostMapping("/licenses/{key}/revoke")
    @Transactional
    public Map<String, Object> revokeLicense(
            @RequestHeader(value = "X-Admin-Token", required = false) String token,
            @PathVariable String key) {
        checkAdmin(token);
        LicenseRecord lic = licenseRepo.findById(key)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        lic.setActive(false);
        licenseRepo.save(lic);
        List<SessionRecord> active = sessionRepo.findByLicenseKeyAndActiveTrueOrderByCreatedAtAsc(key);
        for (SessionRecord s : active) {
            s.setActive(false);
            sessionRepo.save(s);
        }
        return Map.of("ok", true, "licenseKey", key, "active", false, "killedSessions", active.size());
    }

    @PostMapping("/licenses/{key}/reset-hwid")
    @Transactional
    public Map<String, Object> resetHwid(
            @RequestHeader(value = "X-Admin-Token", required = false) String token,
            @PathVariable String key) {
        checkAdmin(token);
        LicenseRecord lic = licenseRepo.findById(key)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        lic.setBoundHwidsCsv("");
        licenseRepo.save(lic);
        return Map.of("ok", true, "licenseKey", key, "boundHwidsReset", true);
    }

    @GetMapping("/sessions")
    public List<Map<String, Object>> activeSessions(
            @RequestHeader(value = "X-Admin-Token", required = false) String token) {
        checkAdmin(token);
        List<Map<String, Object>> out = new ArrayList<>();
        for (SessionRecord s : sessionRepo.findByActiveTrue()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("sessionId", s.getSessionId());
            row.put("licenseKey", s.getLicenseKey());
            row.put("productId", s.getProductId());
            row.put("buildId", s.getBuildId());
            row.put("hwid", s.getHwid());
            row.put("seq", s.getSeq());
            row.put("lastHeartbeatAt", s.getLastHeartbeatAt().toString());
            row.put("expiresAt", s.getExpiresAt().toString());
            row.put("ip", s.getClientIp());
            out.add(row);
        }
        return out;
    }

    @GetMapping("/audit")
    public List<AuditEvent> recentAudit(
            @RequestHeader(value = "X-Admin-Token", required = false) String token) {
        checkAdmin(token);
        return auditRepo.findTop50ByOrderByOccurredAtDesc();
    }
}
