package dev.hydro.j2c.fabric;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Extracts Fabric mod metadata (fabric.mod.json and *.mixins.json) so entrypoints
 * and Mixin contracts are preserved intact while protecting all mod logic.
 */
public final class FabricMetadata {
    private boolean fabricMod;
    private String modId = "";
    private final Set<String> entrypointClasses = new LinkedHashSet<>();
    private final Set<String> entrypointMethodRefs = new LinkedHashSet<>();
    private final Set<String> mixinConfigPaths = new LinkedHashSet<>();
    private final Set<String> mixinClasses = new LinkedHashSet<>();
    private final Set<String> detectedPackages = new LinkedHashSet<>();

    public static FabricMetadata parse(Map<String, byte[]> resources) {
        FabricMetadata meta = new FabricMetadata();
        byte[] modJsonBytes = resources.get("fabric.mod.json");
        if (modJsonBytes == null) {
            return meta;
        }
        meta.fabricMod = true;
        String json = new String(modJsonBytes, StandardCharsets.UTF_8);
        Map<String, Object> root = MiniJson.parseObject(json);
        if (root.get("id") instanceof String id) {
            meta.modId = id;
        }

        if (root.get("entrypoints") instanceof Map<?, ?> eps) {
            for (Object val : eps.values()) {
                collectEntrypointVal(val, meta);
            }
        }

        if (root.get("mixins") instanceof List<?> mixins) {
            for (Object item : mixins) {
                if (item instanceof String s) {
                    meta.mixinConfigPaths.add(s);
                } else if (item instanceof Map<?, ?> m && m.get("config") instanceof String s) {
                    meta.mixinConfigPaths.add(s);
                }
            }
        }

        for (String mixinCfgPath : meta.mixinConfigPaths) {
            byte[] cfgBytes = resources.get(mixinCfgPath);
            if (cfgBytes == null) continue;
            Map<String, Object> cfg = MiniJson.parseObject(new String(cfgBytes, StandardCharsets.UTF_8));
            String pkg = cfg.get("package") instanceof String p ? p.replace('.', '/') : "";
            if (!pkg.isEmpty()) {
                meta.detectedPackages.add(topPackagePrefix(pkg));
            }
            for (String key : List.of("mixins", "client", "server")) {
                if (cfg.get(key) instanceof List<?> list) {
                    for (Object entry : list) {
                        if (entry instanceof String clsName) {
                            String internal = (pkg.isEmpty() ? "" : pkg + "/") + clsName.replace('.', '/');
                            meta.mixinClasses.add(internal);
                        }
                    }
                }
            }
        }
        return meta;
    }

    private static void collectEntrypointVal(Object val, FabricMetadata meta) {
        if (val instanceof List<?> list) {
            for (Object item : list) {
                String value = null;
                if (item instanceof String s) value = s;
                else if (item instanceof Map<?, ?> m && m.get("value") instanceof String s) value = s;
                if (value == null || value.isBlank()) continue;
                int colon = value.indexOf("::");
                String cls = (colon >= 0 ? value.substring(0, colon) : value).trim().replace('.', '/');
                meta.entrypointClasses.add(cls);
                meta.detectedPackages.add(topPackagePrefix(cls));
                if (colon >= 0) {
                    String method = value.substring(colon + 2).trim();
                    meta.entrypointMethodRefs.add(cls + "::" + method);
                }
            }
        }
    }

    private static String topPackagePrefix(String internalName) {
        int slash1 = internalName.indexOf('/');
        if (slash1 < 0) return internalName;
        int slash2 = internalName.indexOf('/', slash1 + 1);
        return slash2 >= 0 ? internalName.substring(0, slash2) : internalName.substring(0, slash1);
    }

    public boolean isFabricMod() { return fabricMod; }
    public String getModId() { return modId; }
    public Set<String> getEntrypointClasses() { return entrypointClasses; }
    public Set<String> getEntrypointMethodRefs() { return entrypointMethodRefs; }
    public Set<String> getMixinConfigPaths() { return mixinConfigPaths; }
    public Set<String> getMixinClasses() { return mixinClasses; }
    public Set<String> getDetectedPackages() { return detectedPackages; }

    public boolean isMixinClass(String internalName) {
        return mixinClasses.contains(internalName);
    }
}
