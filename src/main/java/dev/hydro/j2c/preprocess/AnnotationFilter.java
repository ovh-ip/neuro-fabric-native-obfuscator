package dev.hydro.j2c.preprocess;

import dev.hydro.j2c.config.ObfuscationConfig;
import org.objectweb.asm.Handle;
import org.objectweb.asm.tree.*;

import java.util.*;

/**
 * Evaluates @Native, @NotNative, @NativeVM annotations (supporting both dev.neuro.nativeobfuscator
 * and by.radioegor146.nativeobfuscator descriptors) alongside include/exclude/whitelist/blacklist rules.
 */
public final class AnnotationFilter {

    public static final Set<String> NATIVE_DESCS = Set.of(
            "Ldev/neuro/nativeobfuscator/Native;",
            "Lby/radioegor146/nativeobfuscator/Native;"
    );

    public static final Set<String> NOT_NATIVE_DESCS = Set.of(
            "Ldev/neuro/nativeobfuscator/NotNative;",
            "Lby/radioegor146/nativeobfuscator/NotNative;"
    );

    public static final Set<String> NATIVE_VM_DESCS = Set.of(
            "Ldev/neuro/nativeobfuscator/NativeVM;"
    );

    public static boolean hasClassNative(ClassNode cn) {
        return hasAny(cn.invisibleAnnotations, NATIVE_DESCS)
                || hasAny(cn.visibleAnnotations, NATIVE_DESCS)
                || hasClassNativeVm(cn);
    }

    public static boolean hasClassNativeVm(ClassNode cn) {
        return hasAny(cn.invisibleAnnotations, NATIVE_VM_DESCS)
                || hasAny(cn.visibleAnnotations, NATIVE_VM_DESCS);
    }

    public static boolean hasMethodNative(MethodNode mn) {
        return hasAny(mn.invisibleAnnotations, NATIVE_DESCS)
                || hasAny(mn.visibleAnnotations, NATIVE_DESCS)
                || hasMethodNativeVm(mn);
    }

    public static boolean hasMethodNativeVm(MethodNode mn) {
        return hasAny(mn.invisibleAnnotations, NATIVE_VM_DESCS)
                || hasAny(mn.visibleAnnotations, NATIVE_VM_DESCS);
    }

    public static boolean hasMethodNotNative(MethodNode mn) {
        return hasAny(mn.invisibleAnnotations, NOT_NATIVE_DESCS)
                || hasAny(mn.visibleAnnotations, NOT_NATIVE_DESCS);
    }

    public static boolean shouldProcessClass(ClassNode cn, ObfuscationConfig config) {
        if (isBlacklisted(cn.name, config)) return false;
        if (!matchesWhitelistOrIncludes(cn.name, config)) return false;
        if (!config.isUseAnnotations()) return true;

        if (hasClassNative(cn)) return true;
        if (cn.methods != null) {
            for (MethodNode mn : cn.methods) {
                if (!hasMethodNotNative(mn) && hasMethodNative(mn)) return true;
            }
        }
        return false;
    }

    public static boolean shouldProcessMethod(ClassNode cn, MethodNode mn, ObfuscationConfig config, Set<MethodNode> lambdaTargets) {
        String methodKey = cn.name + "#" + mn.name + "!" + mn.desc;
        String dotMethodKey = cn.name + "." + mn.name;
        for (String exc : config.getExcludePatterns()) {
            if (ObfuscationConfig.matchesGlob(cn.name, exc)
                    || ObfuscationConfig.matchesGlob(dotMethodKey, exc)
                    || exc.equals(methodKey)) {
                return false;
            }
        }
        if (hasMethodNotNative(mn)) return false;

        if (!config.isUseAnnotations()) {
            return true;
        }
        if (hasMethodNative(mn)) return true;
        if (lambdaTargets != null && lambdaTargets.contains(mn)) return true;
        return hasClassNative(cn);
    }

    public static boolean shouldUseVm(ClassNode cn, MethodNode mn) {
        return hasClassNativeVm(cn) || hasMethodNativeVm(mn);
    }

    /**
     * Collects synthetic lambda methods inside `cn` invoked by any method that is itself selected for native compilation.
     */
    public static Set<MethodNode> collectLambdaTargets(ClassNode cn, ObfuscationConfig config) {
        Set<MethodNode> result = Collections.newSetFromMap(new IdentityHashMap<>());
        if (cn.methods == null) return result;
        Map<String, MethodNode> byNameDesc = new HashMap<>();
        for (MethodNode m : cn.methods) byNameDesc.put(m.name + m.desc, m);

        boolean changed = true;
        while (changed) {
            changed = false;
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null) continue;
                boolean active = !config.isUseAnnotations()
                        ? !hasMethodNotNative(mn)
                        : (!hasMethodNotNative(mn) && (hasClassNative(cn) || hasMethodNative(mn) || result.contains(mn)));
                if (!active) continue;
                for (AbstractInsnNode insn : mn.instructions) {
                    if (insn instanceof InvokeDynamicInsnNode indy && indy.bsmArgs != null) {
                        for (Object arg : indy.bsmArgs) {
                            if (arg instanceof Handle h && cn.name.equals(h.getOwner())) {
                                MethodNode target = byNameDesc.get(h.getName() + h.getDesc());
                                if (target != null && !hasMethodNotNative(target) && result.add(target)) {
                                    changed = true;
                                }
                            }
                        }
                    }
                }
            }
        }
        return result;
    }

    public static void cleanAnnotations(ClassNode cn) {
        strip(cn.invisibleAnnotations);
        strip(cn.visibleAnnotations);
        if (cn.methods != null) {
            for (MethodNode mn : cn.methods) {
                strip(mn.invisibleAnnotations);
                strip(mn.visibleAnnotations);
            }
        }
    }

    private static void strip(List<AnnotationNode> list) {
        if (list == null) return;
        list.removeIf(an -> NATIVE_DESCS.contains(an.desc)
                || NOT_NATIVE_DESCS.contains(an.desc)
                || NATIVE_VM_DESCS.contains(an.desc));
    }

    private static boolean hasAny(List<AnnotationNode> list, Set<String> descs) {
        if (list == null) return false;
        for (AnnotationNode an : list) {
            if (descs.contains(an.desc)) return true;
        }
        return false;
    }

    private static boolean isBlacklisted(String internalName, ObfuscationConfig config) {
        for (String exc : config.getExcludePatterns()) {
            if (ObfuscationConfig.matchesGlob(internalName, exc)) return true;
        }
        return false;
    }

    private static boolean matchesWhitelistOrIncludes(String internalName, ObfuscationConfig config) {
        if (config.getIncludePatterns().isEmpty()) return true;
        for (String inc : config.getIncludePatterns()) {
            if (ObfuscationConfig.matchesGlob(internalName, inc)) return true;
        }
        return false;
    }
}
