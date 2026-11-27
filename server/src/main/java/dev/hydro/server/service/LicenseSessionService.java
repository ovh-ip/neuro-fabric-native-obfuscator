package dev.hydro.server.service;

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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;

@Service
public class LicenseSessionService {

    public record HandshakeRequest(
            String productId,
            String buildId,
            String licenseKey,
            String hwid,
            String jarDigest,
            String symDigest,
            String clientPub,
            String clientNonce,
            long ts,
            String proof) {}

    public record HandshakeResponse(
            boolean ok,
            String sessionId,
            String srvEphPub,
            String serverNonce,
            String nonce12,
            String ciphertext,
            String mac) {}

    public record HeartbeatRequest(
            String sessionId,
            long seq,
            long ts,
            String hwid,
            String jarDigest,
            String symDigest,
            String proof) {}

    public record HeartbeatResponse(
            boolean ok,
            long seq,
            String nonce12,
            String ciphertext,
            String mac) {}

    private final BuildRepository buildRepo;
    private final LicenseRepository licenseRepo;
    private final SessionRepository sessionRepo;
    private final AuditEventRepository auditRepo;
    private final ServerCryptoService cryptoService;

    @Value("${hydro.server.heartbeat-interval-sec:15}")
    private int heartbeatIntervalSec;

    @Value("${hydro.server.session-lease-sec:45}")
    private int sessionLeaseSec;

    @Value("${hydro.server.max-clock-skew-sec:120}")
    private long maxClockSkewSec;

    public LicenseSessionService(
            BuildRepository buildRepo,
            LicenseRepository licenseRepo,
            SessionRepository sessionRepo,
            AuditEventRepository auditRepo,
            ServerCryptoService cryptoService) {
        this.buildRepo = buildRepo;
        this.licenseRepo = licenseRepo;
        this.sessionRepo = sessionRepo;
        this.auditRepo = auditRepo;
        this.cryptoService = cryptoService;
    }

    @Transactional
    public HandshakeResponse handshake(HandshakeRequest req, String ip) {
        validateBasicReq(req);

        long nowSec = Instant.now().getEpochSecond();
        if (Math.abs(nowSec - req.ts()) > maxClockSkewSec) {
            audit("REPLAY_SKEW", req.licenseKey(), req.buildId(), req.hwid(), ip, "ts=" + req.ts());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Clock skew rejected");
        }

        BuildRecord build = buildRepo.findByProductIdAndBuildId(req.productId(), req.buildId())
                .orElseThrow(() -> {
                    audit("UNKNOWN_BUILD", req.licenseKey(), req.buildId(), req.hwid(), ip, "product=" + req.productId());
                    return new ResponseStatusException(HttpStatus.FORBIDDEN, "Unknown build");
                });
        if (build.isRevoked()) {
            audit("REVOKED_BUILD", req.licenseKey(), req.buildId(), req.hwid(), ip, "Revoked build");
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Build revoked");
        }

        String jarHex = req.jarDigest().toLowerCase(Locale.ROOT);
        String symHex = req.symDigest().toLowerCase(Locale.ROOT);
        if (!HydroCrypto.constantTimeEquals(jarHex, build.getJarDigest().toLowerCase(Locale.ROOT))
                || !HydroCrypto.constantTimeEquals(symHex, build.getSymDigest().toLowerCase(Locale.ROOT))) {
            audit("INTEGRITY_MISMATCH", req.licenseKey(), req.buildId(), req.hwid(), ip,
                    "jar=" + jarHex + " sym=" + symHex);
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Binary integrity check failed");
        }

        LicenseRecord lic = licenseRepo.findById(req.licenseKey())
                .orElseThrow(() -> {
                    audit("BAD_LICENSE", req.licenseKey(), req.buildId(), req.hwid(), ip, "Not found");
                    return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid license");
                });

        Instant now = Instant.now();
        if (!lic.isActive() || now.isAfter(lic.getExpiresAt())
                || (!"*".equals(lic.getProductId()) && !lic.getProductId().equals(req.productId()))) {
            audit("LICENSE_INACTIVE", req.licenseKey(), req.buildId(), req.hwid(), ip,
                    "active=" + lic.isActive() + " exp=" + lic.getExpiresAt());
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "License inactive or expired");
        }

        byte[] clientPub = decodeFixedHex(req.clientPub(), 32, "clientPub");
        byte[] clientNonce = decodeFixedHex(req.clientNonce(), 16, "clientNonce");
        byte[] proofBytes = decodeFixedHex(req.proof(), 32, "proof");

        byte[] dhStatic = HydroCrypto.x25519(cryptoService.getStaticPrivateKey(), clientPub);
        byte[] hsAuthKey = HydroCrypto.hkdfSha256(
                clientNonce, dhStatic, ("HY-HS-AUTH|" + req.buildId()).getBytes(StandardCharsets.UTF_8), 32);
        String authMsg = req.productId() + "|" + req.buildId() + "|" + req.licenseKey()
                + "|" + req.hwid() + "|" + jarHex + "|" + symHex + "|" + req.ts() + "|" + req.clientPub().toLowerCase(Locale.ROOT);
        byte[] expectedProof = HydroCrypto.hmacSha256(hsAuthKey, authMsg.getBytes(StandardCharsets.UTF_8));
        if (!HydroCrypto.constantTimeEquals(expectedProof, proofBytes)) {
            audit("BAD_CRYPTO_PROOF", req.licenseKey(), req.buildId(), req.hwid(), ip, "Handshake X25519 proof mismatch");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Cryptographic proof rejected");
        }

        // Enforce HWID binding slots
        List<String> boundHwids = parseCsv(lic.getBoundHwidsCsv());
        if (!boundHwids.contains(req.hwid())) {
            if (boundHwids.size() >= Math.max(1, lic.getMaxHwids())) {
                audit("HWID_REJECTED", req.licenseKey(), req.buildId(), req.hwid(), ip,
                        "Bound=" + boundHwids.size() + " Max=" + lic.getMaxHwids());
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "HWID limit reached");
            }
            boundHwids.add(req.hwid());
            lic.setBoundHwidsCsv(String.join(",", boundHwids));
            licenseRepo.save(lic);
        }

        // Enforce maxConcurrentSessions (evict oldest session(s) immediately so concurrent crackers fail on next heartbeat)
        List<SessionRecord> activeSessions = sessionRepo.findByLicenseKeyAndActiveTrueOrderByCreatedAtAsc(lic.getLicenseKey());
        int maxConc = Math.max(1, lic.getMaxConcurrentSessions());
        while (activeSessions.size() >= maxConc) {
            SessionRecord oldest = activeSessions.remove(0);
            oldest.setActive(false);
            sessionRepo.save(oldest);
            audit("SESSION_EVICTED", lic.getLicenseKey(), oldest.getBuildId(), oldest.getHwid(), ip,
                    "Evicted session " + oldest.getSessionId() + " by new login");
        }

        // Derive double-DH forward-secret session keys
        byte[] srvEphPriv = HydroCrypto.clampX25519Scalar(HydroCrypto.randomBytes(32, cryptoService.getRng()));
        byte[] srvEphPub = HydroCrypto.x25519PublicKey(srvEphPriv);
        byte[] dhEph = HydroCrypto.x25519(srvEphPriv, clientPub);
        byte[] serverNonce = HydroCrypto.randomBytes(16, cryptoService.getRng());
        String sessionId = HydroCrypto.toHex(HydroCrypto.randomBytes(16, cryptoService.getRng()));

        byte[] ikm = HydroCrypto.concat(dhStatic, dhEph);
        byte[] salt = HydroCrypto.concat(clientNonce, serverNonce);
        byte[] masterSessKey = HydroCrypto.hkdfSha256(
                salt, ikm, ("HY-SESS-V1|" + req.buildId() + "|" + req.hwid()).getBytes(StandardCharsets.UTF_8), 32);
        byte[] encKey = HydroCrypto.hkdfExpand(masterSessKey, "ENC".getBytes(StandardCharsets.UTF_8), 32);
        byte[] macKey = HydroCrypto.hkdfExpand(masterSessKey, "MAC".getBytes(StandardCharsets.UTF_8), 32);
        byte[] rollingKey = HydroCrypto.hmacSha256(
                masterSessKey, ("ROLL0|" + sessionId + "|" + HydroCrypto.toHex(serverNonce)).getBytes(StandardCharsets.UTF_8));

        String srvEphPubHex = HydroCrypto.toHex(srvEphPub);
        String plaintext = build.getVmShareHex() + "|"
                + build.getVaultShareHex() + "|"
                + HydroCrypto.toHex(rollingKey) + "|"
                + heartbeatIntervalSec + "|"
                + sessionLeaseSec + "|"
                + build.getDynParamsHex();

        byte[] nonce12 = HydroCrypto.randomBytes(12, cryptoService.getRng());
        byte[] ct = HydroCrypto.chacha20Xor(encKey, nonce12, 1, plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] aad = (sessionId + "|" + req.buildId() + "|" + req.hwid() + "|"
                + req.clientPub().toLowerCase(Locale.ROOT) + "|" + srvEphPubHex).getBytes(StandardCharsets.UTF_8);
        byte[] mac = HydroCrypto.hmacSha256(macKey, HydroCrypto.concat(aad, nonce12, ct));

        SessionRecord sess = new SessionRecord();
        sess.setSessionId(sessionId);
        sess.setLicenseKey(lic.getLicenseKey());
        sess.setProductId(req.productId());
        sess.setBuildId(req.buildId());
        sess.setHwid(req.hwid());
        sess.setMasterSessionKeyHex(HydroCrypto.toHex(masterSessKey));
        sess.setEncKeyHex(HydroCrypto.toHex(encKey));
        sess.setMacKeyHex(HydroCrypto.toHex(macKey));
        sess.setRollingKeyHex(HydroCrypto.toHex(rollingKey));
        sess.setClientPubHex(req.clientPub().toLowerCase(Locale.ROOT));
        sess.setSeq(0L);
        sess.setActive(true);
        sess.setLastHeartbeatAt(now);
        sess.setExpiresAt(now.plusSeconds(sessionLeaseSec));
        sess.setClientIp(ip);
        sessionRepo.save(sess);

        audit("HANDSHAKE_OK", lic.getLicenseKey(), req.buildId(), req.hwid(), ip, "session=" + sessionId);
        return new HandshakeResponse(
                true, sessionId, srvEphPubHex, HydroCrypto.toHex(serverNonce),
                HydroCrypto.toHex(nonce12), HydroCrypto.toHex(ct), HydroCrypto.toHex(mac));
    }

    @Transactional
    public HeartbeatResponse heartbeat(HeartbeatRequest req, String ip) {
        if (req == null || req.sessionId() == null || req.hwid() == null || req.proof() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Malformed heartbeat");
        }
        SessionRecord sess = sessionRepo.findById(req.sessionId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unknown session"));

        Instant now = Instant.now();
        if (!sess.isActive() || now.isAfter(sess.getExpiresAt())) {
            sess.setActive(false);
            sessionRepo.save(sess);
            audit("HB_EXPIRED", sess.getLicenseKey(), sess.getBuildId(), req.hwid(), ip, "session=" + sess.getSessionId());
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Session expired or revoked");
        }
        if (!HydroCrypto.constantTimeEquals(req.hwid(), sess.getHwid())) {
            sess.setActive(false);
            sessionRepo.save(sess);
            audit("HB_HWID_SPOOF", sess.getLicenseKey(), sess.getBuildId(), req.hwid(), ip, "expected=" + sess.getHwid());
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "HWID mismatch");
        }
        if (Math.abs(now.getEpochSecond() - req.ts()) > maxClockSkewSec) {
            audit("HB_REPLAY_SKEW", sess.getLicenseKey(), sess.getBuildId(), req.hwid(), ip, "ts=" + req.ts());
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Clock skew rejected");
        }
        if (req.seq() != sess.getSeq() + 1L) {
            sess.setActive(false);
            sessionRepo.save(sess);
            audit("HB_SEQ_REPLAY", sess.getLicenseKey(), sess.getBuildId(), req.hwid(), ip,
                    "got=" + req.seq() + " expected=" + (sess.getSeq() + 1L));
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Sequence replay detected");
        }

        LicenseRecord lic = licenseRepo.findById(sess.getLicenseKey()).orElse(null);
        BuildRecord build = buildRepo.findByProductIdAndBuildId(sess.getProductId(), sess.getBuildId()).orElse(null);
        if (lic == null || !lic.isActive() || now.isAfter(lic.getExpiresAt()) || build == null || build.isRevoked()) {
            sess.setActive(false);
            sessionRepo.save(sess);
            audit("HB_REVOKED", sess.getLicenseKey(), sess.getBuildId(), req.hwid(), ip, "License or build revoked");
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Revoked");
        }

        String jarHex = req.jarDigest() == null ? "" : req.jarDigest().toLowerCase(Locale.ROOT);
        String symHex = req.symDigest() == null ? "" : req.symDigest().toLowerCase(Locale.ROOT);
        if (!HydroCrypto.constantTimeEquals(jarHex, build.getJarDigest().toLowerCase(Locale.ROOT))
                || !HydroCrypto.constantTimeEquals(symHex, build.getSymDigest().toLowerCase(Locale.ROOT))) {
            sess.setActive(false);
            sessionRepo.save(sess);
            audit("HB_TAMPER", sess.getLicenseKey(), sess.getBuildId(), req.hwid(), ip, "Live binary modified");
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Live integrity check failed");
        }

        byte[] proofBytes = decodeFixedHex(req.proof(), 32, "proof");
        byte[] curRollingKey = HydroCrypto.fromHex(sess.getRollingKeyHex());
        String msg = sess.getSessionId() + "|" + req.seq() + "|" + req.ts() + "|" + req.hwid() + "|" + jarHex + "|" + symHex;
        byte[] expected = HydroCrypto.hmacSha256(curRollingKey, msg.getBytes(StandardCharsets.UTF_8));
        if (!HydroCrypto.constantTimeEquals(expected, proofBytes)) {
            sess.setActive(false);
            sessionRepo.save(sess);
            audit("HB_BAD_PROOF", sess.getLicenseKey(), sess.getBuildId(), req.hwid(), ip, "Rolling key mismatch");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid heartbeat proof");
        }

        byte[] masterSessKey = HydroCrypto.fromHex(sess.getMasterSessionKeyHex());
        byte[] encKey = HydroCrypto.fromHex(sess.getEncKeyHex());
        byte[] macKey = HydroCrypto.fromHex(sess.getMacKeyHex());
        byte[] sNonce2 = HydroCrypto.randomBytes(16, cryptoService.getRng());
        byte[] nextRollingKey = HydroCrypto.hmacSha256(
                masterSessKey,
                ("ROLL|" + sess.getSessionId() + "|" + req.seq() + "|" + HydroCrypto.toHex(sNonce2)).getBytes(StandardCharsets.UTF_8));

        sess.setSeq(req.seq());
        sess.setRollingKeyHex(HydroCrypto.toHex(nextRollingKey));
        sess.setLastHeartbeatAt(now);
        sess.setExpiresAt(now.plusSeconds(sessionLeaseSec));
        sessionRepo.save(sess);

        String pt = req.seq() + "|" + HydroCrypto.toHex(nextRollingKey) + "|"
                + heartbeatIntervalSec + "|" + sessionLeaseSec + "|1";
        byte[] nonce12 = HydroCrypto.randomBytes(12, cryptoService.getRng());
        byte[] ct = HydroCrypto.chacha20Xor(encKey, nonce12, 1, pt.getBytes(StandardCharsets.UTF_8));
        byte[] aad = ("HB|" + sess.getSessionId() + "|" + req.seq()).getBytes(StandardCharsets.UTF_8);
        byte[] mac = HydroCrypto.hmacSha256(macKey, HydroCrypto.concat(aad, nonce12, ct));

        return new HeartbeatResponse(true, req.seq(), HydroCrypto.toHex(nonce12), HydroCrypto.toHex(ct), HydroCrypto.toHex(mac));
    }

    @Transactional
    public void logout(String sessionId, String proofHex, String ip) {
        if (sessionId == null || proofHex == null) return;
        sessionRepo.findById(sessionId).ifPresent(sess -> {
            byte[] rk = HydroCrypto.fromHex(sess.getRollingKeyHex());
            byte[] expected = HydroCrypto.hmacSha256(rk, ("LOGOUT|" + sessionId).getBytes(StandardCharsets.UTF_8));
            byte[] given = HydroCrypto.fromHex(proofHex);
            if (HydroCrypto.constantTimeEquals(expected, given)) {
                sess.setActive(false);
                sessionRepo.save(sess);
                audit("LOGOUT_OK", sess.getLicenseKey(), sess.getBuildId(), sess.getHwid(), ip, "session=" + sessionId);
            }
        });
    }

    @Scheduled(fixedDelay = 15000)
    @Transactional
    public void reapExpiredSessions() {
        List<SessionRecord> expired = sessionRepo.findByActiveTrueAndExpiresAtBefore(Instant.now());
        for (SessionRecord s : expired) {
            s.setActive(false);
            sessionRepo.save(s);
        }
    }

    private void validateBasicReq(HandshakeRequest req) {
        if (req == null || isBlank(req.productId()) || isBlank(req.buildId())
                || isBlank(req.licenseKey()) || isBlank(req.hwid())
                || isBlank(req.jarDigest()) || isBlank(req.symDigest())
                || isBlank(req.clientPub()) || isBlank(req.clientNonce()) || isBlank(req.proof())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Missing handshake fields");
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private static byte[] decodeFixedHex(String hex, int bytes, String field) {
        try {
            byte[] b = HydroCrypto.fromHex(hex);
            if (b.length != bytes) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid " + field);
            return b;
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid hex in " + field);
        }
    }

    private static List<String> parseCsv(String csv) {
        List<String> list = new ArrayList<>();
        if (csv != null && !csv.isBlank()) {
            for (String p : csv.split(",")) {
                if (!p.isBlank()) list.add(p.trim());
            }
        }
        return list;
    }

    public void audit(String type, String licKey, String buildId, String hwid, String ip, String details) {
        AuditEvent ev = new AuditEvent();
        ev.setEventType(type);
        ev.setLicenseKey(licKey);
        ev.setBuildId(buildId);
        ev.setHwid(hwid);
        ev.setIp(ip);
        ev.setDetails(details != null && details.length() > 500 ? details.substring(0, 500) : details);
        auditRepo.save(ev);
    }
}
