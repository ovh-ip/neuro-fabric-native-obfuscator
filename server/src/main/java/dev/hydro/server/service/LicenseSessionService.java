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
import java.util.concurrent.ConcurrentHashMap;

@Service
public class LicenseSessionService {

    /** Encrypted client handshake envelope: k=clientPub(64h), n=clientNonce(32h), v=nonce12(24h), p=ct, m=mac(64h). */
    public record HandshakeRequest(String k, String n, String v, String p, String m) {}

    public record HandshakeResponse(boolean ok, String s, String k, String n, String v, String p, String m) {}

    /** Encrypted heartbeat envelope: s=sessionId, q=seq, v=nonce12(24h), p=ct, m=mac(64h). */
    public record HeartbeatRequest(String s, long q, String v, String p, String m) {}

    public record HeartbeatResponse(boolean ok, long q, String v, String p, String m) {}

    /** Encrypted logout envelope: s=sessionId, v=nonce12(24h), p=ct, m=mac(64h). */
    public record LogoutRequest(String s, String v, String p, String m) {}

    private final BuildRepository buildRepo;
    private final LicenseRepository licenseRepo;
    private final SessionRepository sessionRepo;
    private final AuditEventRepository auditRepo;
    private final ServerCryptoService cryptoService;
    private final ConcurrentHashMap<String, Long> handshakeReplayCache = new ConcurrentHashMap<>();

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
        if (req == null || isBlank(req.k()) || isBlank(req.n()) || isBlank(req.v()) || isBlank(req.p()) || isBlank(req.m())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Malformed envelope");
        }
        String kHex = req.k().toLowerCase(Locale.ROOT);
        String nHex = req.n().toLowerCase(Locale.ROOT);
        byte[] clientPub = decodeFixedHex(kHex, 32, "k");
        byte[] clientNonce = decodeFixedHex(nHex, 16, "n");
        byte[] reqNonce12 = decodeFixedHex(req.v(), 12, "v");
        byte[] reqCt = decodeVarHex(req.p(), 2048, "p");
        byte[] reqMac = decodeFixedHex(req.m(), 32, "m");

        long nowSec = Instant.now().getEpochSecond();
        String replayKey = kHex + ":" + nHex;
        if (handshakeReplayCache.size() > 50_000) {
            handshakeReplayCache.entrySet().removeIf(e -> e.getValue() < nowSec);
        }
        Long prevExp = handshakeReplayCache.putIfAbsent(replayKey, nowSec + Math.max(60L, maxClockSkewSec * 2L));
        if (prevExp != null && prevExp >= nowSec) {
            audit("HS_REPLAY", "", "", "", ip, "k=" + kHex.substring(0, 16));
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Handshake replay rejected");
        }

        byte[] dhStatic = HydroCrypto.x25519(cryptoService.getStaticPrivateKey(), clientPub);
        byte[] reqEncKey = HydroCrypto.hkdfSha256(clientNonce, dhStatic, "HY-REQ-E2".getBytes(StandardCharsets.UTF_8), 32);
        byte[] reqMacKey = HydroCrypto.hkdfSha256(clientNonce, dhStatic, "HY-REQ-M2".getBytes(StandardCharsets.UTF_8), 32);

        byte[] reqAad = (kHex + "|" + nHex).getBytes(StandardCharsets.UTF_8);
        byte[] expectedReqMac = HydroCrypto.hmacSha256(reqMacKey, HydroCrypto.concat(reqAad, reqNonce12, reqCt));
        if (!HydroCrypto.constantTimeEquals(expectedReqMac, reqMac)) {
            audit("BAD_HS_MAC", "", "", "", ip, "Handshake E2EE MAC mismatch");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Envelope authentication rejected");
        }

        String inner = new String(HydroCrypto.chacha20Xor(reqEncKey, reqNonce12, 1, reqCt), StandardCharsets.UTF_8);
        // Inner plaintext format: productId|buildId|licenseKey|hwid|jarHex|symHex|ts|kHex
        String[] parts = inner.split("\\|", -1);
        if (parts.length != 8) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid inner payload");
        }
        String productId = parts[0];
        String buildId = parts[1];
        String licenseKey = parts[2];
        String hwid = parts[3].toLowerCase(Locale.ROOT);
        String jarHex = parts[4].toLowerCase(Locale.ROOT);
        String symHex = parts[5].toLowerCase(Locale.ROOT);
        long reqTs = parseLongStrict(parts[6]);
        String innerPubHex = parts[7].toLowerCase(Locale.ROOT);

        if (isBlank(productId) || isBlank(buildId) || isBlank(licenseKey) || isBlank(hwid)
                || !HydroCrypto.constantTimeEquals(innerPubHex, kHex)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Bound key mismatch");
        }
        if (Math.abs(nowSec - reqTs) > maxClockSkewSec) {
            audit("REPLAY_SKEW", licenseKey, buildId, hwid, ip, "ts=" + reqTs);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Clock skew rejected");
        }

        BuildRecord build = buildRepo.findByProductIdAndBuildId(productId, buildId)
                .orElseThrow(() -> {
                    audit("UNKNOWN_BUILD", licenseKey, buildId, hwid, ip, "product=" + productId);
                    return new ResponseStatusException(HttpStatus.FORBIDDEN, "Unknown build");
                });
        if (build.isRevoked()) {
            audit("REVOKED_BUILD", licenseKey, buildId, hwid, ip, "Revoked build");
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Build revoked");
        }
        if (!HydroCrypto.constantTimeEquals(jarHex, build.getJarDigest().toLowerCase(Locale.ROOT))
                || !HydroCrypto.constantTimeEquals(symHex, build.getSymDigest().toLowerCase(Locale.ROOT))) {
            audit("INTEGRITY_MISMATCH", licenseKey, buildId, hwid, ip, "jar=" + jarHex + " sym=" + symHex);
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Binary integrity check failed");
        }

        LicenseRecord lic = licenseRepo.findById(licenseKey)
                .orElseThrow(() -> {
                    audit("BAD_LICENSE", licenseKey, buildId, hwid, ip, "Not found");
                    return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid license");
                });
        Instant now = Instant.now();
        if (!lic.isActive() || now.isAfter(lic.getExpiresAt())
                || (!"*".equals(lic.getProductId()) && !lic.getProductId().equals(productId))) {
            audit("LICENSE_INACTIVE", licenseKey, buildId, hwid, ip,
                    "active=" + lic.isActive() + " exp=" + lic.getExpiresAt());
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "License inactive or expired");
        }

        // Enforce HWID binding slots
        List<String> boundHwids = parseCsv(lic.getBoundHwidsCsv());
        if (!boundHwids.contains(hwid)) {
            if (boundHwids.size() >= Math.max(1, lic.getMaxHwids())) {
                audit("HWID_REJECTED", licenseKey, buildId, hwid, ip,
                        "Bound=" + boundHwids.size() + " Max=" + lic.getMaxHwids());
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "HWID limit reached");
            }
            boundHwids.add(hwid);
            lic.setBoundHwidsCsv(String.join(",", boundHwids));
            licenseRepo.save(lic);
        }

        // Enforce maxConcurrentSessions (evict oldest active session(s) immediately)
        List<SessionRecord> activeSessions = sessionRepo.findByLicenseKeyAndActiveTrueOrderByCreatedAtAsc(lic.getLicenseKey());
        int maxConc = Math.max(1, lic.getMaxConcurrentSessions());
        while (activeSessions.size() >= maxConc) {
            SessionRecord oldest = activeSessions.remove(0);
            oldest.setActive(false);
            sessionRepo.save(oldest);
            audit("SESSION_EVICTED", lic.getLicenseKey(), oldest.getBuildId(), oldest.getHwid(), ip,
                    "Evicted session " + oldest.getSessionId());
        }

        // Double-DH forward-secret session derivation
        byte[] srvEphPriv = HydroCrypto.clampX25519Scalar(HydroCrypto.randomBytes(32, cryptoService.getRng()));
        byte[] srvEphPub = HydroCrypto.x25519PublicKey(srvEphPriv);
        byte[] dhEph = HydroCrypto.x25519(srvEphPriv, clientPub);
        byte[] serverNonce = HydroCrypto.randomBytes(16, cryptoService.getRng());
        String sNonceHex = HydroCrypto.toHex(serverNonce);
        String sessionId = HydroCrypto.toHex(HydroCrypto.randomBytes(16, cryptoService.getRng()));

        byte[] ikm = HydroCrypto.concat(dhStatic, dhEph);
        byte[] salt = HydroCrypto.concat(clientNonce, serverNonce);
        byte[] masterSessKey = HydroCrypto.hkdfSha256(
                salt, ikm, ("HY-SESS-V2|" + buildId + "|" + hwid).getBytes(StandardCharsets.UTF_8), 32);
        byte[] encKey = HydroCrypto.hkdfExpand(masterSessKey, "E".getBytes(StandardCharsets.UTF_8), 32);
        byte[] macKey = HydroCrypto.hkdfExpand(masterSessKey, "M".getBytes(StandardCharsets.UTF_8), 32);
        byte[] rollingKey = HydroCrypto.hkdfExpand(masterSessKey, ("R|" + sessionId + "|" + sNonceHex).getBytes(StandardCharsets.UTF_8), 32);
        String guardHex = HydroCrypto.toHex(Arrays.copyOf(
                HydroCrypto.hkdfExpand(masterSessKey, ("G|" + sessionId).getBytes(StandardCharsets.UTF_8), 8), 8));

        String srvEphPubHex = HydroCrypto.toHex(srvEphPub);
        String plaintext = build.getVmShareHex() + "|"
                + build.getVaultShareHex() + "|"
                + HydroCrypto.toHex(rollingKey) + "|"
                + heartbeatIntervalSec + "|"
                + sessionLeaseSec + "|"
                + nowSec + "|"
                + guardHex + "|"
                + build.getDynParamsHex();

        byte[] nonce12 = HydroCrypto.randomBytes(12, cryptoService.getRng());
        byte[] ct = HydroCrypto.chacha20Xor(encKey, nonce12, 1, plaintext.getBytes(StandardCharsets.UTF_8));
        byte[] aad = (sessionId + "|" + buildId + "|" + hwid + "|" + kHex + "|" + srvEphPubHex).getBytes(StandardCharsets.UTF_8);
        byte[] mac = HydroCrypto.hmacSha256(macKey, HydroCrypto.concat(aad, nonce12, ct));

        SessionRecord sess = new SessionRecord();
        sess.setSessionId(sessionId);
        sess.setLicenseKey(lic.getLicenseKey());
        sess.setProductId(productId);
        sess.setBuildId(buildId);
        sess.setHwid(hwid);
        sess.setMasterSessionKeyHex(HydroCrypto.toHex(masterSessKey));
        sess.setEncKeyHex(HydroCrypto.toHex(encKey));
        sess.setMacKeyHex(HydroCrypto.toHex(macKey));
        sess.setRollingKeyHex(HydroCrypto.toHex(rollingKey));
        sess.setSessionGuardHex(guardHex);
        sess.setClientPubHex(kHex);
        sess.setSeq(0L);
        sess.setActive(true);
        sess.setLastHeartbeatAt(now);
        sess.setExpiresAt(now.plusSeconds(sessionLeaseSec));
        sess.setClientIp(ip);
        sessionRepo.save(sess);

        audit("HANDSHAKE_OK", lic.getLicenseKey(), buildId, hwid, ip, "session=" + sessionId);
        return new HandshakeResponse(
                true, sessionId, srvEphPubHex, sNonceHex,
                HydroCrypto.toHex(nonce12), HydroCrypto.toHex(ct), HydroCrypto.toHex(mac));
    }

    @Transactional
    public HeartbeatResponse heartbeat(HeartbeatRequest req, String ip) {
        if (req == null || isBlank(req.s()) || isBlank(req.v()) || isBlank(req.p()) || isBlank(req.m())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Malformed heartbeat");
        }
        SessionRecord sess = sessionRepo.findById(req.s())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unknown session"));

        Instant now = Instant.now();
        long nowSec = now.getEpochSecond();
        if (!sess.isActive() || now.isAfter(sess.getExpiresAt())) {
            sess.setActive(false);
            sessionRepo.save(sess);
            audit("HB_EXPIRED", sess.getLicenseKey(), sess.getBuildId(), sess.getHwid(), ip, "session=" + sess.getSessionId());
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Session expired or revoked");
        }
        if (req.q() != sess.getSeq() + 1L) {
            sess.setActive(false);
            sessionRepo.save(sess);
            audit("HB_SEQ_REPLAY", sess.getLicenseKey(), sess.getBuildId(), sess.getHwid(), ip,
                    "got=" + req.q() + " expected=" + (sess.getSeq() + 1L));
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Sequence replay detected");
        }

        byte[] curEncKey = HydroCrypto.fromHex(sess.getEncKeyHex());
        byte[] curMacKey = HydroCrypto.fromHex(sess.getMacKeyHex());
        byte[] curRollingKey = HydroCrypto.fromHex(sess.getRollingKeyHex());

        byte[] reqNonce12 = decodeFixedHex(req.v(), 12, "v");
        byte[] reqCt = decodeVarHex(req.p(), 1024, "p");
        byte[] reqMac = decodeFixedHex(req.m(), 32, "m");
        byte[] reqAad = ("HBQ|" + sess.getSessionId() + "|" + req.q()).getBytes(StandardCharsets.UTF_8);
        byte[] expectedReqMac = HydroCrypto.hmacSha256(curMacKey, HydroCrypto.concat(reqAad, reqNonce12, reqCt));
        if (!HydroCrypto.constantTimeEquals(expectedReqMac, reqMac)) {
            sess.setActive(false);
            sessionRepo.save(sess);
            audit("HB_BAD_MAC", sess.getLicenseKey(), sess.getBuildId(), sess.getHwid(), ip, "Ciphertext MAC mismatch");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Encrypted heartbeat rejected");
        }

        String inner = new String(HydroCrypto.chacha20Xor(curEncKey, reqNonce12, 1, reqCt), StandardCharsets.UTF_8);
        // Inner format: ts|hwid|jarHex|symHex|guardHex|proofHex
        String[] parts = inner.split("\\|", -1);
        if (parts.length != 6) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Malformed heartbeat payload");
        }
        long reqTs = parseLongStrict(parts[0]);
        String hwid = parts[1].toLowerCase(Locale.ROOT);
        String jarHex = parts[2].toLowerCase(Locale.ROOT);
        String symHex = parts[3].toLowerCase(Locale.ROOT);
        String guardHex = parts[4].toLowerCase(Locale.ROOT);
        String proofHex = parts[5].toLowerCase(Locale.ROOT);

        if (!HydroCrypto.constantTimeEquals(hwid, sess.getHwid())) {
            sess.setActive(false);
            sessionRepo.save(sess);
            audit("HB_HWID_SPOOF", sess.getLicenseKey(), sess.getBuildId(), hwid, ip, "expected=" + sess.getHwid());
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "HWID mismatch");
        }
        if (Math.abs(nowSec - reqTs) > maxClockSkewSec) {
            audit("HB_REPLAY_SKEW", sess.getLicenseKey(), sess.getBuildId(), hwid, ip, "ts=" + reqTs);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Clock skew rejected");
        }

        LicenseRecord lic = licenseRepo.findById(sess.getLicenseKey()).orElse(null);
        BuildRecord build = buildRepo.findByProductIdAndBuildId(sess.getProductId(), sess.getBuildId()).orElse(null);
        if (lic == null || !lic.isActive() || now.isAfter(lic.getExpiresAt()) || build == null || build.isRevoked()) {
            sess.setActive(false);
            sessionRepo.save(sess);
            audit("HB_REVOKED", sess.getLicenseKey(), sess.getBuildId(), hwid, ip, "License or build revoked");
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Revoked");
        }
        if (!HydroCrypto.constantTimeEquals(jarHex, build.getJarDigest().toLowerCase(Locale.ROOT))
                || !HydroCrypto.constantTimeEquals(symHex, build.getSymDigest().toLowerCase(Locale.ROOT))) {
            sess.setActive(false);
            sessionRepo.save(sess);
            audit("HB_TAMPER", sess.getLicenseKey(), sess.getBuildId(), hwid, ip, "Live binary modified");
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Live integrity check failed");
        }

        byte[] proofBytes = decodeFixedHex(proofHex, 32, "proof");
        String msg = sess.getSessionId() + "|" + req.q() + "|" + reqTs + "|" + hwid + "|" + jarHex + "|" + symHex + "|" + guardHex;
        byte[] expectedProof = HydroCrypto.hmacSha256(curRollingKey, msg.getBytes(StandardCharsets.UTF_8));
        if (!HydroCrypto.constantTimeEquals(guardHex, sess.getSessionGuardHex())
                || !HydroCrypto.constantTimeEquals(expectedProof, proofBytes)) {
            sess.setActive(false);
            sessionRepo.save(sess);
            audit("HB_BAD_PROOF", sess.getLicenseKey(), sess.getBuildId(), hwid, ip, "Rolling/guard mismatch");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid heartbeat proof");
        }

        // Full 3-key + guard forward-secret ratcheting
        byte[] masterSessKey = HydroCrypto.fromHex(sess.getMasterSessionKeyHex());
        byte[] sNonce2 = HydroCrypto.randomBytes(16, cryptoService.getRng());
        byte[] epoch = HydroCrypto.hmacSha256(
                masterSessKey,
                ("RAT2|" + sess.getSessionId() + "|" + req.q() + "|" + HydroCrypto.toHex(sNonce2)).getBytes(StandardCharsets.UTF_8));
        byte[] nextEncKey = HydroCrypto.hkdfExpand(epoch, "E".getBytes(StandardCharsets.UTF_8), 32);
        byte[] nextMacKey = HydroCrypto.hkdfExpand(epoch, "M".getBytes(StandardCharsets.UTF_8), 32);
        byte[] nextRollingKey = HydroCrypto.hkdfExpand(epoch, "R".getBytes(StandardCharsets.UTF_8), 32);
        String nextGuardHex = HydroCrypto.toHex(Arrays.copyOf(
                HydroCrypto.hkdfExpand(epoch, "G".getBytes(StandardCharsets.UTF_8), 8), 8));

        sess.setSeq(req.q());
        sess.setEncKeyHex(HydroCrypto.toHex(nextEncKey));
        sess.setMacKeyHex(HydroCrypto.toHex(nextMacKey));
        sess.setRollingKeyHex(HydroCrypto.toHex(nextRollingKey));
        sess.setSessionGuardHex(nextGuardHex);
        sess.setLastHeartbeatAt(now);
        sess.setExpiresAt(now.plusSeconds(sessionLeaseSec));
        sessionRepo.save(sess);

        // Encrypt response under PREVIOUS (curEncKey, curMacKey) so client switches atomically on receipt
        String pt = req.q() + "|" + HydroCrypto.toHex(epoch) + "|" + heartbeatIntervalSec + "|" + sessionLeaseSec + "|" + nowSec + "|1";
        byte[] nonce12 = HydroCrypto.randomBytes(12, cryptoService.getRng());
        byte[] ct = HydroCrypto.chacha20Xor(curEncKey, nonce12, 1, pt.getBytes(StandardCharsets.UTF_8));
        byte[] aad = ("HB|" + sess.getSessionId() + "|" + req.q()).getBytes(StandardCharsets.UTF_8);
        byte[] mac = HydroCrypto.hmacSha256(curMacKey, HydroCrypto.concat(aad, nonce12, ct));

        return new HeartbeatResponse(true, req.q(), HydroCrypto.toHex(nonce12), HydroCrypto.toHex(ct), HydroCrypto.toHex(mac));
    }

    @Transactional
    public void logout(LogoutRequest req, String ip) {
        if (req == null || isBlank(req.s()) || isBlank(req.v()) || isBlank(req.p()) || isBlank(req.m())) return;
        sessionRepo.findById(req.s()).ifPresent(sess -> {
            if (!sess.isActive()) return;
            try {
                byte[] encKey = HydroCrypto.fromHex(sess.getEncKeyHex());
                byte[] macKey = HydroCrypto.fromHex(sess.getMacKeyHex());
                byte[] rk = HydroCrypto.fromHex(sess.getRollingKeyHex());
                byte[] n12 = decodeFixedHex(req.v(), 12, "v");
                byte[] ct = decodeVarHex(req.p(), 512, "p");
                byte[] mac = decodeFixedHex(req.m(), 32, "m");
                byte[] aad = ("LOQ|" + sess.getSessionId()).getBytes(StandardCharsets.UTF_8);
                byte[] expMac = HydroCrypto.hmacSha256(macKey, HydroCrypto.concat(aad, n12, ct));
                if (!HydroCrypto.constantTimeEquals(expMac, mac)) return;

                String inner = new String(HydroCrypto.chacha20Xor(encKey, n12, 1, ct), StandardCharsets.UTF_8);
                String[] parts = inner.split("\\|", -1);
                if (parts.length != 3) return;
                long ts = parseLongStrict(parts[0]);
                if (Math.abs(Instant.now().getEpochSecond() - ts) > maxClockSkewSec) return;
                if (!HydroCrypto.constantTimeEquals(parts[1].toLowerCase(Locale.ROOT), sess.getSessionGuardHex())) return;
                byte[] expectedProof = HydroCrypto.hmacSha256(rk, ("LOGOUT|" + sess.getSessionId() + "|" + ts).getBytes(StandardCharsets.UTF_8));
                byte[] given = HydroCrypto.fromHex(parts[2]);
                if (HydroCrypto.constantTimeEquals(expectedProof, given)) {
                    sess.setActive(false);
                    sessionRepo.save(sess);
                    audit("LOGOUT_OK", sess.getLicenseKey(), sess.getBuildId(), sess.getHwid(), ip, "session=" + sess.getSessionId());
                }
            } catch (Exception ignored) {}
        });
    }

    @Scheduled(fixedDelay = 15000)
    @Transactional
    public void reapExpiredSessions() {
        long nowSec = Instant.now().getEpochSecond();
        handshakeReplayCache.entrySet().removeIf(e -> e.getValue() < nowSec);
        List<SessionRecord> expired = sessionRepo.findByActiveTrueAndExpiresAtBefore(Instant.now());
        for (SessionRecord s : expired) {
            s.setActive(false);
            sessionRepo.save(s);
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }

    private static long parseLongStrict(String s) {
        try {
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid numeric field");
        }
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

    private static byte[] decodeVarHex(String hex, int maxBytes, String field) {
        try {
            byte[] b = HydroCrypto.fromHex(hex);
            if (b.length == 0 || b.length > maxBytes) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid length in " + field);
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
