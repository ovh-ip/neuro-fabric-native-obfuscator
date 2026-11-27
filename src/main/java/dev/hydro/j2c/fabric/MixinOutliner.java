package dev.hydro.j2c.fabric;

import dev.hydro.j2c.config.ObfuscationConfig;
import dev.hydro.j2c.preprocess.AnnotationFilter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.util.*;

/**
 * Safely protects SpongePowered Mixin classes without breaking Mixin's bytecode merger.
 *
 * Because SpongePowered Mixin parses and inlines @Inject/@Overwrite/@Redirect/@Modify* bodies
 * directly into Minecraft target classes at runtime, marking those hook methods directly as
 * {@code native} would break Mixin injection. Instead, MixinOutliner extracts each hook body
 * into a dedicated synthetic bridge class (whose method IS compiled to native C++ in the .dll)
 * and leaves a tiny 1-call trampoline inside the @Mixin class.
 */
public final class MixinOutliner {

    private static final Set<String> HOOK_ANNOTATIONS = Set.of(
            "Lorg/spongepowered/asm/mixin/injection/Inject;",
            "Lorg/spongepowered/asm/mixin/injection/Redirect;",
            "Lorg/spongepowered/asm/mixin/injection/ModifyArg;",
            "Lorg/spongepowered/asm/mixin/injection/ModifyArgs;",
            "Lorg/spongepowered/asm/mixin/injection/ModifyConstant;",
            "Lorg/spongepowered/asm/mixin/injection/ModifyVariable;",
            "Lorg/spongepowered/asm/mixin/Overwrite;",
            "Lcom/llamalad7/mixinextras/injector/wrapoperation/WrapOperation;",
            "Lcom/llamalad7/mixinextras/injector/ModifyExpressionValue;",
            "Lcom/llamalad7/mixinextras/injector/ModifyReturnValue;",
            "Lcom/llamalad7/mixinextras/injector/v2/WrapWithCondition;",
            "Lcom/llamalad7/mixinextras/injector/wrapmethod/WrapMethod;"
    );

    private static final String MIXIN_ANN = "Lorg/spongepowered/asm/mixin/Mixin;";
    private static final String SHADOW_ANN = "Lorg/spongepowered/asm/mixin/Shadow;";
    private static final String ACCESSOR_ANN = "Lorg/spongepowered/asm/mixin/gen/Accessor;";
    private static final String INVOKER_ANN = "Lorg/spongepowered/asm/mixin/gen/Invoker;";

    public static final class MixinContext {
        public final String mixinInternalName;
        public final List<String> targets;
        public final Set<String> shadowFields;
        public final Set<String> shadowMethods;
        public final Set<String> declaredMembers;

        public MixinContext(String mixinInternalName, List<String> targets,
                            Set<String> shadowFields, Set<String> shadowMethods,
                            Set<String> declaredMembers) {
            this.mixinInternalName = mixinInternalName;
            this.targets = targets;
            this.shadowFields = shadowFields;
            this.shadowMethods = shadowMethods;
            this.declaredMembers = declaredMembers;
        }
    }

    public static String resolveFieldOwner(String owner, String name, String desc, MixinContext mixinCtx) {
        if (mixinCtx != null && owner.equals(mixinCtx.mixinInternalName)
                && !mixinCtx.declaredMembers.contains("F:" + name + ":" + desc)
                && mixinCtx.targets.size() == 1) {
            return mixinCtx.targets.get(0);
        }
        return owner;
    }

    public static String resolveMethodOwner(String owner, String name, String desc, MixinContext mixinCtx) {
        if (mixinCtx != null && owner.equals(mixinCtx.mixinInternalName)
                && !mixinCtx.declaredMembers.contains("M:" + name + desc)
                && mixinCtx.targets.size() == 1) {
            return mixinCtx.targets.get(0);
        }
        return owner;
    }

    public static boolean isDynamicFieldAccess(String owner, String name, String desc, boolean isStatic, MixinContext mixinCtx) {
        return mixinCtx != null && !isStatic
                && owner.equals(mixinCtx.mixinInternalName)
                && !mixinCtx.declaredMembers.contains("F:" + name + ":" + desc)
                && mixinCtx.targets.size() != 1;
    }

    public static boolean isDynamicMethodAccess(String owner, String name, String desc, boolean isStatic, MixinContext mixinCtx) {
        return mixinCtx != null && !isStatic
                && owner.equals(mixinCtx.mixinInternalName)
                && (mixinCtx.targets.size() != 1 || mixinCtx.declaredMembers.contains("M:" + name + desc));
    }

    public static boolean isMixinClass(ClassNode cn, FabricMetadata meta) {
        if (meta.isMixinClass(cn.name)) return true;
        return hasAnnotation(cn.visibleAnnotations, MIXIN_ANN)
                || hasAnnotation(cn.invisibleAnnotations, MIXIN_ANN);
    }

    public static List<ClassNode> outlineMixins(
            Collection<ClassNode> classes,
            FabricMetadata meta,
            ObfuscationConfig config,
            Map<MethodNode, MixinContext> bridgeContexts,
            Set<ClassNode> generatedBridges,
            Set<String> mixinTargetsOut,
            String loaderInternalName,
            String bootMethodName,
            Random rng) {

        List<ClassNode> newlyAdded = new ArrayList<>();
        int bridgeCounter = 0;

        for (ClassNode cn : new ArrayList<>(classes)) {
            if (!isMixinClass(cn, meta)) continue;
            if ((cn.access & Opcodes.ACC_INTERFACE) != 0) continue;
            if (config.isUseAnnotations() && !AnnotationFilter.shouldProcessClass(cn, config)) continue;

            List<String> targets = extractMixinTargets(cn);
            mixinTargetsOut.addAll(targets);
            Set<String> shadowFields = new HashSet<>();
            Set<String> shadowMethods = new HashSet<>();
            Set<String> declaredMembers = new HashSet<>();

            if (cn.fields != null) {
                for (FieldNode fn : cn.fields) {
                    if (hasAnnotation(fn.visibleAnnotations, SHADOW_ANN)
                            || hasAnnotation(fn.invisibleAnnotations, SHADOW_ANN)) {
                        shadowFields.add(fn.name + ":" + fn.desc);
                    } else {
                        declaredMembers.add("F:" + fn.name + ":" + fn.desc);
                    }
                }
            }
            if (cn.methods != null) {
                for (MethodNode mn : cn.methods) {
                    if (hasAnnotation(mn.visibleAnnotations, SHADOW_ANN)
                            || hasAnnotation(mn.invisibleAnnotations, SHADOW_ANN)) {
                        shadowMethods.add(mn.name + mn.desc);
                    } else {
                        declaredMembers.add("M:" + mn.name + mn.desc);
                    }
                }
            }

            MixinContext ctx = new MixinContext(cn.name, targets, shadowFields, shadowMethods, declaredMembers);

            ClassNode bridge = null;
            int methodIdx = 0;

            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if (mn.name.equals("<init>") || mn.name.equals("<clinit>")) continue;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
                if (hasAnyAnnotation(mn, Set.of(SHADOW_ANN, ACCESSOR_ANN, INVOKER_ANN))) continue;
                if (!AnnotationFilter.shouldProcessMethod(cn, mn, config, null)) continue;

                boolean isHook = hasAnyAnnotation(mn, HOOK_ANNOTATIONS);
                boolean isNonTrivialHelper = countRealInsns(mn) >= 4;
                if (!isHook && !isNonTrivialHelper && !(config.isUseAnnotations() && AnnotationFilter.hasMethodNative(mn))) continue;

                // Skip outlining if method uses INVOKESPECIAL to super on non-static (rare in Mixins, handle cleanly)
                // Actually CppMethodEmitter supports CallNonvirtual for super! Only skip if method has weird JSR or empty.
                if (bridge == null) {
                    String pkg = cn.name.contains("/") ? cn.name.substring(0, cn.name.lastIndexOf('/')) : "hydro/bridge";
                    String bridgeName = pkg + "/$HM_" + Integer.toUnsignedString(rng.nextInt(), 36) + "_" + (bridgeCounter++);
                    bridge = new ClassNode();
                    bridge.version = Math.max(cn.version, Opcodes.V17);
                    bridge.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
                    bridge.name = bridgeName;
                    bridge.superName = "java/lang/Object";
                    newlyAdded.add(bridge);
                    generatedBridges.add(bridge);
                }

                boolean isStatic = (mn.access & Opcodes.ACC_STATIC) != 0;
                Type origType = Type.getMethodType(mn.desc);
                Type[] origArgs = origType.getArgumentTypes();
                Type[] bridgeArgs;
                if (isStatic) {
                    bridgeArgs = origArgs;
                } else {
                    bridgeArgs = new Type[origArgs.length + 1];
                    bridgeArgs[0] = Type.getObjectType("java/lang/Object");
                    System.arraycopy(origArgs, 0, bridgeArgs, 1, origArgs.length);
                }
                String bridgeDesc = Type.getMethodDescriptor(origType.getReturnType(), bridgeArgs);
                String bridgeMethodName = "h$" + (methodIdx++);

                MethodNode outlined = new MethodNode(
                        Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                        bridgeMethodName,
                        bridgeDesc,
                        null,
                        mn.exceptions != null ? mn.exceptions.toArray(new String[0]) : null
                );

                // Copy instructions & try-catch blocks with cloned labels
                Map<LabelNode, LabelNode> labelMap = new IdentityHashMap<>();
                for (AbstractInsnNode insn : mn.instructions) {
                    if (insn instanceof LabelNode l) {
                        labelMap.put(l, new LabelNode());
                    }
                }
                for (AbstractInsnNode insn : mn.instructions) {
                    outlined.instructions.add(insn.clone(labelMap));
                }
                if (mn.tryCatchBlocks != null) {
                    outlined.tryCatchBlocks = new ArrayList<>();
                    for (TryCatchBlockNode tcb : mn.tryCatchBlocks) {
                        outlined.tryCatchBlocks.add(new TryCatchBlockNode(
                                labelMap.get(tcb.start),
                                labelMap.get(tcb.end),
                                labelMap.get(tcb.handler),
                                tcb.type
                        ));
                    }
                }
                outlined.maxStack = mn.maxStack;
                outlined.maxLocals = mn.maxLocals;
                bridge.methods.add(outlined);
                bridgeContexts.put(outlined, ctx);

                // Replace Mixin hook body with clean 1-call trampoline (prefixed with HLoader boot trigger)
                InsnList tramp = new InsnList();
                if (loaderInternalName != null && bootMethodName != null) {
                    tramp.add(new MethodInsnNode(Opcodes.INVOKESTATIC, loaderInternalName, bootMethodName, "()V", false));
                }
                int slot = 0;
                if (!isStatic) {
                    tramp.add(new VarInsnNode(Opcodes.ALOAD, 0));
                    slot = 1;
                }
                for (Type arg : origArgs) {
                    tramp.add(new VarInsnNode(arg.getOpcode(Opcodes.ILOAD), slot));
                    slot += arg.getSize();
                }
                tramp.add(new MethodInsnNode(Opcodes.INVOKESTATIC, bridge.name, bridgeMethodName, bridgeDesc, false));
                tramp.add(new InsnNode(origType.getReturnType().getOpcode(Opcodes.IRETURN)));

                mn.instructions = tramp;
                mn.tryCatchBlocks = new ArrayList<>();
                mn.localVariables = null;
                mn.maxStack = Math.max(4, slot + 2);
                mn.maxLocals = Math.max(mn.maxLocals, slot);
            }
        }
        return newlyAdded;
    }

    private static int countRealInsns(MethodNode mn) {
        int c = 0;
        for (AbstractInsnNode insn : mn.instructions) {
            if (insn.getOpcode() >= 0) c++;
        }
        return c;
    }

    @SuppressWarnings("unchecked")
    private static List<String> extractMixinTargets(ClassNode cn) {
        List<String> targets = new ArrayList<>();
        List<AnnotationNode> all = new ArrayList<>();
        if (cn.visibleAnnotations != null) all.addAll(cn.visibleAnnotations);
        if (cn.invisibleAnnotations != null) all.addAll(cn.invisibleAnnotations);
        for (AnnotationNode an : all) {
            if (!MIXIN_ANN.equals(an.desc) || an.values == null) continue;
            for (int i = 0; i + 1 < an.values.size(); i += 2) {
                String k = (String) an.values.get(i);
                Object v = an.values.get(i + 1);
                if ("value".equals(k) && v instanceof List<?> list) {
                    for (Object o : list) {
                        if (o instanceof Type t) targets.add(t.getInternalName());
                    }
                } else if ("targets".equals(k) && v instanceof List<?> list) {
                    for (Object o : list) {
                        if (o instanceof String s) targets.add(s.replace('.', '/'));
                    }
                }
            }
        }
        return targets;
    }

    private static boolean hasAnyAnnotation(MethodNode mn, Set<String> anns) {
        if (mn.visibleAnnotations != null) {
            for (AnnotationNode an : mn.visibleAnnotations) {
                if (anns.contains(an.desc)) return true;
            }
        }
        if (mn.invisibleAnnotations != null) {
            for (AnnotationNode an : mn.invisibleAnnotations) {
                if (anns.contains(an.desc)) return true;
            }
        }
        return false;
    }

    private static boolean hasAnnotation(List<AnnotationNode> list, String desc) {
        if (list == null) return false;
        for (AnnotationNode an : list) {
            if (desc.equals(an.desc)) return true;
        }
        return false;
    }
}
