package dev.hydro.server.crypto;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Loads or generates the server's pinned static X25519 keypair and Admin API bearer token.
 */
@Service
public class ServerCryptoService {

    private final SecureRandom rng = new SecureRandom();
    private final ObjectMapper mapper = new ObjectMapper();

    @Value("${hydro.server.keys-file:./data/server-keys.json}")
    private String keysFilePath;

    private byte[] staticPrivateKey;
    private byte[] staticPublicKey;
    private String staticPublicKeyHex;
    private String adminToken;

    @PostConstruct
    public void init() throws Exception {
        String envPriv = System.getenv("HYDRO_SERVER_PRIVKEY");
        String envAdmin = System.getenv("HYDRO_ADMIN_TOKEN");
        Path p = Path.of(keysFilePath);

        if (envPriv != null && !envPriv.isBlank()) {
            this.staticPrivateKey = HydroCrypto.clampX25519Scalar(HydroCrypto.fromHex(envPriv));
            this.staticPublicKey = HydroCrypto.x25519PublicKey(this.staticPrivateKey);
            this.staticPublicKeyHex = HydroCrypto.toHex(this.staticPublicKey);
            this.adminToken = (envAdmin != null && !envAdmin.isBlank())
                    ? envAdmin
                    : HydroCrypto.toHex(HydroCrypto.randomBytes(24, rng));
        } else if (Files.isRegularFile(p)) {
            @SuppressWarnings("unchecked")
            Map<String, String> saved = mapper.readValue(Files.readString(p), Map.class);
            this.staticPrivateKey = HydroCrypto.clampX25519Scalar(HydroCrypto.fromHex(saved.get("staticPrivHex")));
            this.staticPublicKey = HydroCrypto.x25519PublicKey(this.staticPrivateKey);
            this.staticPublicKeyHex = HydroCrypto.toHex(this.staticPublicKey);
            this.adminToken = (envAdmin != null && !envAdmin.isBlank()) ? envAdmin : saved.get("adminToken");
        } else {
            this.staticPrivateKey = HydroCrypto.clampX25519Scalar(HydroCrypto.randomBytes(32, rng));
            this.staticPublicKey = HydroCrypto.x25519PublicKey(this.staticPrivateKey);
            this.staticPublicKeyHex = HydroCrypto.toHex(this.staticPublicKey);
            this.adminToken = (envAdmin != null && !envAdmin.isBlank())
                    ? envAdmin
                    : HydroCrypto.toHex(HydroCrypto.randomBytes(24, rng));
            if (p.getParent() != null) Files.createDirectories(p.getParent());
            Map<String, String> out = new LinkedHashMap<>();
            out.put("staticPrivHex", HydroCrypto.toHex(this.staticPrivateKey));
            out.put("staticPubHex", this.staticPublicKeyHex);
            out.put("adminToken", this.adminToken);
            Files.writeString(p, mapper.writerWithDefaultPrettyPrinter().writeValueAsString(out));
        }

        System.out.println("============================================================");
        System.out.println("[HydroServer] Pinned Server X25519 PubKey (--server-pubkey):");
        System.out.println("  " + this.staticPublicKeyHex);
        System.out.println("[HydroServer] Admin Token (X-Admin-Token): " + this.adminToken);
        System.out.println("============================================================");
    }

    public byte[] getStaticPrivateKey() { return staticPrivateKey; }
    public byte[] getStaticPublicKey() { return staticPublicKey; }
    public String getStaticPublicKeyHex() { return staticPublicKeyHex; }
    public String getAdminToken() { return adminToken; }
    public SecureRandom getRng() { return rng; }
}
