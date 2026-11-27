package dev.hydro.j2c.jar;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.jar.Attributes;
import java.util.jar.Manifest;

/**
 * Extracts standard JAR metadata (META-INF/MANIFEST.MF and META-INF/services/*)
 * so runnable JARs, Java agents, SPI providers, and plain libraries run cleanly with full protection.
 */
public final class JarMetadata {

    private boolean hasManifest;
    private String mainClass = "";
    private final Set<String> entrypointClasses = new LinkedHashSet<>();
    private final Set<String> spiClasses = new LinkedHashSet<>();

    public static JarMetadata parse(Map<String, byte[]> resources) {
        JarMetadata meta = new JarMetadata();
        byte[] mfBytes = resources.get("META-INF/MANIFEST.MF");
        if (mfBytes != null) {
            meta.hasManifest = true;
            try {
                Manifest mf = new Manifest(new ByteArrayInputStream(mfBytes));
                Attributes attrs = mf.getMainAttributes();
                String mc = extractClass(attrs.getValue("Main-Class"));
                if (mc != null) {
                    meta.mainClass = mc;
                    meta.entrypointClasses.add(mc);
                }
                for (String key : List.of("Start-Class", "Premain-Class", "Agent-Class", "Launcher-Agent-Class")) {
                    String val = extractClass(attrs.getValue(key));
                    if (val != null) {
                        meta.entrypointClasses.add(val);
                    }
                }
            } catch (Exception ignored) {
            }
        }

        for (Map.Entry<String, byte[]> e : resources.entrySet()) {
            String path = e.getKey();
            if (!path.startsWith("META-INF/services/") || path.endsWith("/")) continue;
            String text = new String(e.getValue(), StandardCharsets.UTF_8);
            for (String rawLine : text.split("\\R")) {
                int comment = rawLine.indexOf('#');
                String line = (comment >= 0 ? rawLine.substring(0, comment) : rawLine).trim();
                if (!line.isEmpty()) {
                    meta.spiClasses.add(line.replace('.', '/'));
                }
            }
        }
        return meta;
    }

    private static String extractClass(String raw) {
        if (raw == null || raw.isBlank()) return null;
        return raw.trim().replace('.', '/');
    }

    public boolean hasManifest() { return hasManifest; }
    public String getMainClass() { return mainClass; }
    public Set<String> getEntrypointClasses() { return entrypointClasses; }
    public Set<String> getSpiClasses() { return spiClasses; }
}
