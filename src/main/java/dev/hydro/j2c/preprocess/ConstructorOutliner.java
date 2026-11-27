package dev.hydro.j2c.preprocess;

import dev.hydro.j2c.analysis.FrameAnalyzer;
import dev.hydro.j2c.config.ObfuscationConfig;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.*;

/**
 * Outlines the post-super(...) constructor body of <init> methods into a private native method
 * so even constructor logic is protected in the native .dll while preserving JVM verifier rules.
 */
public final class ConstructorOutliner {

    public static void outlineConstructors(ClassNode cn, ObfuscationConfig config, Set<MethodNode> outlinedTargets) {
        outlineConstructors(cn, config, outlinedTargets, new Random(cn.name.hashCode()));
    }

    public static void outlineConstructors(ClassNode cn, ObfuscationConfig config, Set<MethodNode> outlinedTargets, Random rng) {
        if ((cn.access & Opcodes.ACC_INTERFACE) != 0) return;
        List<MethodNode> newMethods = new ArrayList<>();
        Set<String> usedNames = new HashSet<>();
        for (MethodNode m : cn.methods) usedNames.add(m.name);

        for (MethodNode mn : cn.methods) {
            if (!"<init>".equals(mn.name)) continue;
            if (!AnnotationFilter.shouldProcessMethod(cn, mn, config, null)) continue;
            if (mn.instructions == null || mn.instructions.size() == 0) continue;
            if ((mn.access & Opcodes.ACC_ABSTRACT) != 0) continue;

            AbstractInsnNode superCall = findOwnSuperInitCall(cn, mn);
            if (superCall == null) continue;

            // Ensure no jump or try-catch spans across the superCall boundary
            int superIdx = mn.instructions.indexOf(superCall);
            if (superIdx < 0) continue;

            int tailCount = countRealInsnsAfter(mn, superCall);
            if (tailCount <= 1) continue; // Only bare `return`

            if (!canSplitSafely(mn, superIdx)) continue;

            Frame<FrameAnalyzer.TypedValue>[] frames;
            try {
                frames = FrameAnalyzer.analyze(cn.name, mn);
            } catch (Exception e) {
                continue;
            }
            if (superIdx + 1 >= frames.length || frames[superIdx + 1] == null) continue;
            Frame<FrameAnalyzer.TypedValue> postFrame = frames[superIdx + 1];
            if (postFrame.getStackSize() != 0) continue;

            // Build parameter list for all initialized live locals (local 0 is `this`)
            List<Integer> liveSlots = new ArrayList<>();
            List<Type> paramTypes = new ArrayList<>();
            int maxLocals = postFrame.getLocals();
            for (int slot = 1; slot < maxLocals; ) {
                FrameAnalyzer.TypedValue val = postFrame.getLocal(slot);
                if (val == null || val.kind == FrameAnalyzer.Kind.UNINITIALIZED) {
                    slot++;
                    continue;
                }
                Type t = toParamType(val);
                if (t == null) {
                    slot++;
                    continue;
                }
                liveSlots.add(slot);
                paramTypes.add(t);
                slot += t.getSize();
            }

            String helperName;
            do {
                helperName = "c_" + Long.toUnsignedString(rng.nextLong() & 0xFFFFFFFFL, 36);
            } while (!usedNames.add(helperName));
            String helperDesc = Type.getMethodDescriptor(Type.VOID_TYPE, paramTypes.toArray(new Type[0]));
            MethodNode helper = new MethodNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_SYNTHETIC,
                    helperName,
                    helperDesc,
                    null,
                    mn.exceptions != null ? mn.exceptions.toArray(new String[0]) : null
            );

            // Map old local slots -> helper local slots (slot 0 = this, then liveSlots)
            Map<Integer, Integer> slotMap = new HashMap<>();
            slotMap.put(0, 0);
            int nextNewSlot = 1;
            for (int i = 0; i < liveSlots.size(); i++) {
                int oldSlot = liveSlots.get(i);
                slotMap.put(oldSlot, nextNewSlot);
                nextNewSlot += paramTypes.get(i).getSize();
            }

            // Remap any additional higher local slots created after superCall
            int extraBase = Math.max(nextNewSlot, mn.maxLocals);
            Map<LabelNode, LabelNode> labelMap = new IdentityHashMap<>();
            List<AbstractInsnNode> tailNodes = new ArrayList<>();
            for (AbstractInsnNode cur = superCall.getNext(); cur != null; cur = cur.getNext()) {
                tailNodes.add(cur);
                if (cur instanceof LabelNode l) {
                    labelMap.put(l, new LabelNode());
                }
            }

            // Only proceed if every jump target and try-catch block lies strictly after superCall
            boolean validRefs = true;
            for (AbstractInsnNode n : tailNodes) {
                if (n instanceof JumpInsnNode j && !labelMap.containsKey(j.label)) { validRefs = false; break; }
                if (n instanceof TableSwitchInsnNode ts) {
                    if (!labelMap.containsKey(ts.dflt)) { validRefs = false; break; }
                    for (LabelNode l : ts.labels) if (!labelMap.containsKey(l)) { validRefs = false; break; }
                }
                if (n instanceof LookupSwitchInsnNode ls) {
                    if (!labelMap.containsKey(ls.dflt)) { validRefs = false; break; }
                    for (LabelNode l : ls.labels) if (!labelMap.containsKey(l)) { validRefs = false; break; }
                }
            }
            if (!validRefs) continue;

            for (AbstractInsnNode cur : tailNodes) {
                AbstractInsnNode cloned = cur.clone(labelMap);
                if (cloned instanceof VarInsnNode v) {
                    v.var = slotMap.computeIfAbsent(v.var, k -> extraBase + k);
                } else if (cloned instanceof IincInsnNode inc) {
                    inc.var = slotMap.computeIfAbsent(inc.var, k -> extraBase + k);
                }
                helper.instructions.add(cloned);
            }

            if (mn.tryCatchBlocks != null) {
                helper.tryCatchBlocks = new ArrayList<>();
                for (TryCatchBlockNode tcb : mn.tryCatchBlocks) {
                    if (labelMap.containsKey(tcb.start) && labelMap.containsKey(tcb.end) && labelMap.containsKey(tcb.handler)) {
                        helper.tryCatchBlocks.add(new TryCatchBlockNode(
                                labelMap.get(tcb.start), labelMap.get(tcb.end), labelMap.get(tcb.handler), tcb.type));
                    }
                }
            }
            helper.maxStack = mn.maxStack;
            helper.maxLocals = extraBase + mn.maxLocals + 4;
            newMethods.add(helper);
            outlinedTargets.add(helper);

            // Rewrite original <init> tail after superCall to call helper + return
            InsnList prefix = new InsnList();
            for (AbstractInsnNode cur = mn.instructions.getFirst(); cur != null; cur = cur.getNext()) {
                prefix.add(cur.clone(new IdentityHashMap<>() {{
                    for (AbstractInsnNode n : mn.instructions) {
                        if (n instanceof LabelNode l) put(l, l);
                    }
                }}));
                if (cur == superCall) break;
            }
            prefix.add(new VarInsnNode(Opcodes.ALOAD, 0));
            for (int i = 0; i < liveSlots.size(); i++) {
                prefix.add(new VarInsnNode(paramTypes.get(i).getOpcode(Opcodes.ILOAD), liveSlots.get(i)));
            }
            prefix.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, cn.name, helperName, helperDesc, false));
            prefix.add(new InsnNode(Opcodes.RETURN));

            mn.instructions = prefix;
            mn.tryCatchBlocks = new ArrayList<>();
            mn.localVariables = null;
            mn.maxStack = Math.max(mn.maxStack, nextNewSlot + 2);
        }

        cn.methods.addAll(newMethods);

        // Also outline <clinit> body into a static helper so static initializers & secret strings move into .dll!
        for (MethodNode mn : new ArrayList<>(cn.methods)) {
            if (!"<clinit>".equals(mn.name) || !"()V".equals(mn.desc)) continue;
            if (config.isUseAnnotations() && !AnnotationFilter.hasClassNative(cn)) continue;
            if (mn.instructions == null || countRealInsns(mn) <= 1) continue;

            String helperName;
            do {
                helperName = "s_" + Long.toUnsignedString(rng.nextLong() & 0xFFFFFFFFL, 36);
            } while (!usedNames.add(helperName));

            MethodNode helper = new MethodNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                    helperName,
                    "()V",
                    null,
                    mn.exceptions != null ? mn.exceptions.toArray(new String[0]) : null
            );
            Map<LabelNode, LabelNode> lmap = new IdentityHashMap<>();
            for (AbstractInsnNode insn : mn.instructions) {
                if (insn instanceof LabelNode l) lmap.put(l, new LabelNode());
            }
            for (AbstractInsnNode insn : mn.instructions) {
                helper.instructions.add(insn.clone(lmap));
            }
            if (mn.tryCatchBlocks != null) {
                helper.tryCatchBlocks = new ArrayList<>();
                for (TryCatchBlockNode tcb : mn.tryCatchBlocks) {
                    helper.tryCatchBlocks.add(new TryCatchBlockNode(
                            lmap.get(tcb.start), lmap.get(tcb.end), lmap.get(tcb.handler), tcb.type));
                }
            }
            helper.maxStack = mn.maxStack;
            helper.maxLocals = mn.maxLocals;
            cn.methods.add(helper);
            outlinedTargets.add(helper);

            InsnList stub = new InsnList();
            stub.add(new MethodInsnNode(Opcodes.INVOKESTATIC, cn.name, helperName, "()V", false));
            stub.add(new InsnNode(Opcodes.RETURN));
            mn.instructions = stub;
            mn.tryCatchBlocks = new ArrayList<>();
            mn.localVariables = null;
            mn.maxStack = 2;
            mn.maxLocals = 0;
        }
    }

    private static int countRealInsns(MethodNode mn) {
        int c = 0;
        for (AbstractInsnNode cur : mn.instructions) {
            if (cur.getOpcode() >= 0) c++;
        }
        return c;
    }

    private static AbstractInsnNode findOwnSuperInitCall(ClassNode cn, MethodNode mn) {
        int newDepth = 0;
        for (AbstractInsnNode cur : mn.instructions) {
            int op = cur.getOpcode();
            if (op == Opcodes.NEW) {
                newDepth++;
            } else if (cur instanceof MethodInsnNode m && op == Opcodes.INVOKESPECIAL && "<init>".equals(m.name)) {
                if (newDepth == 0 && (m.owner.equals(cn.superName) || m.owner.equals(cn.name))) {
                    return cur;
                }
                if (newDepth > 0) newDepth--;
            }
        }
        return null;
    }

    private static boolean canSplitSafely(MethodNode mn, int superIdx) {
        if (mn.tryCatchBlocks != null) {
            for (TryCatchBlockNode tcb : mn.tryCatchBlocks) {
                int s = mn.instructions.indexOf(tcb.start);
                int e = mn.instructions.indexOf(tcb.end);
                if (s <= superIdx && e > superIdx) return false;
                if (s <= superIdx) return false;
            }
        }
        for (int i = 0; i <= superIdx; i++) {
            AbstractInsnNode n = mn.instructions.get(i);
            if (n instanceof JumpInsnNode j && mn.instructions.indexOf(j.label) > superIdx) return false;
            if (n instanceof TableSwitchInsnNode || n instanceof LookupSwitchInsnNode) return false;
        }
        return true;
    }

    private static int countRealInsnsAfter(MethodNode mn, AbstractInsnNode marker) {
        int count = 0;
        for (AbstractInsnNode cur = marker.getNext(); cur != null; cur = cur.getNext()) {
            if (cur.getOpcode() >= 0) count++;
        }
        return count;
    }

    private static Type toParamType(FrameAnalyzer.TypedValue v) {
        return switch (v.kind) {
            case INT -> Type.INT_TYPE;
            case FLOAT -> Type.FLOAT_TYPE;
            case LONG -> Type.LONG_TYPE;
            case DOUBLE -> Type.DOUBLE_TYPE;
            case REFERENCE -> v.type != null ? v.type : Type.getObjectType("java/lang/Object");
            default -> null;
        };
    }
}
