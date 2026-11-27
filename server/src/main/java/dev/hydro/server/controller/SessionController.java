package dev.hydro.server.controller;

import dev.hydro.server.crypto.ServerCryptoService;
import dev.hydro.server.service.LicenseSessionService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1")
public class SessionController {

    private final LicenseSessionService sessionService;
    private final ServerCryptoService cryptoService;

    public SessionController(LicenseSessionService sessionService, ServerCryptoService cryptoService) {
        this.sessionService = sessionService;
        this.cryptoService = cryptoService;
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of(
                "status", "UP",
                "serverPubHex", cryptoService.getStaticPublicKeyHex()
        );
    }

    @PostMapping("/session/handshake")
    public LicenseSessionService.HandshakeResponse handshake(
            @RequestBody LicenseSessionService.HandshakeRequest req,
            HttpServletRequest httpReq) {
        return sessionService.handshake(req, clientIp(httpReq));
    }

    @PostMapping("/session/heartbeat")
    public LicenseSessionService.HeartbeatResponse heartbeat(
            @RequestBody LicenseSessionService.HeartbeatRequest req,
            HttpServletRequest httpReq) {
        return sessionService.heartbeat(req, clientIp(httpReq));
    }

    @PostMapping("/session/logout")
    public Map<String, Object> logout(
            @RequestBody Map<String, String> body,
            HttpServletRequest httpReq) {
        sessionService.logout(body.get("sessionId"), body.get("proof"), clientIp(httpReq));
        return Map.of("ok", true);
    }

    private static String clientIp(HttpServletRequest req) {
        String xff = req.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) return xff.split(",")[0].trim();
        return req.getRemoteAddr();
    }
}
