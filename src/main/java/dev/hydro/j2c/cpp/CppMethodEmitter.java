package dev.hydro.j2c.cpp;

import dev.hydro.j2c.analysis.ControlFlowGraph;
import dev.hydro.j2c.analysis.FrameAnalyzer;
import dev.hydro.j2c.config.ObfuscationConfig;
import dev.hydro.j2c.crypto.CryptoEngine;
import dev.hydro.j2c.crypto.SymbolPool;
import dev.hydro.j2c.fabric.MixinOutliner;
import dev.hydro.j2c.preprocess.IndyLowerer;
import dev.hydro.j2c.vm.VmCompiler;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.*;

/**
 * Compiles a JVM MethodNode into hardened C++20 native code featuring:
 * - Control-Flow Flattening (CFF) with randomized non-linear state transitions
 * - Mixed Boolean-Arithmetic (MBA) constant & arithmetic synthesis
 * - Opaque predicates + decoy bogus dead basic blocks
 * - Exact JVM semantics (unsigned overflow math, NaN/saturation, INT_MIN/-1, boolean[] vs byte[])
 * - Zero-leak ref-counted JNI RefTable and full Try/Catch/Finally unwinding
 * - Mixin @Shadow dynamic target resolution
 */
public final class CppMethodEmitter implements Opcodes {

    public static String emitMethod(
            String ownerInternal,
            MethodNode mn,
            String cFuncName,
            Frame<FrameAnalyzer.TypedValue>[] frames,
            ControlFlowGraph cfg,
            MixinOutliner.MixinContext mixinCtx,
            SymbolPool pool,
            CryptoEngine crypto,
            ObfuscationConfig config,
            Random rng) {

        boolean strong = config.getTier() != ObfuscationConfig.ProtectionTier.FAST;
        boolean useBogus = config.getTier() != ObfuscationConfig.ProtectionTier.FAST;
        boolean isStatic = (mn.access & ACC_STATIC) != 0;
        Type mt = Type.getMethodType(mn.desc);
        Type[] args = mt.getArgumentTypes();
        Type retType = mt.getReturnType();

        StringBuilder sb = new StringBuilder(4096);
        sb.append("extern \"C\" ").append(jniRetType(retType)).append(" JNICALL ")
          .append(cFuncName).append("(JNIEnv* env, ").append(isStatic ? "jclass" : "jobject").append(" _self_cls");
        for (int i = 0; i < args.length; i++) {
            sb.append(", ").append(jniParamType(args[i])).append(" _p").append(i);
        }
        sb.append(") {\n");

        // Runtime ref pool & opaque seed & live server session check
        sb.append("    hy::RefTable _refs(env);\n");
        sb.append("    uint64_t _op = hy::opaque_seed();\n");
        sb.append("    if (!hy::check_session_alive()) [[unlikely]] return").append(defaultRetExpr(retType)).append(";\n");

        // Track which local slots & kinds exist
        boolean[] needI = new boolean[Math.max(1, mn.maxLocals + 4)];
        boolean[] needJ = new boolean[Math.max(1, mn.maxLocals + 4)];
        boolean[] needF = new boolean[Math.max(1, mn.maxLocals + 4)];
        boolean[] needD = new boolean[Math.max(1, mn.maxLocals + 4)];
        boolean[] needL = new boolean[Math.max(1, mn.maxLocals + 4)];

        if (!isStatic) needL[0] = true;
        int paramSlot = isStatic ? 0 : 1;
        for (Type a : args) {
            markLocalKind(a.getSort(), paramSlot, needI, needJ, needF, needD, needL);
            paramSlot += a.getSize();
        }
        for (Frame<FrameAnalyzer.TypedValue> f : frames) {
            if (f == null) continue;
            for (int l = 0; l < f.getLocals(); l++) {
                FrameAnalyzer.TypedValue v = f.getLocal(l);
                if (v == null) continue;
                switch (v.kind) {
                    case INT -> needI[l] = true;
                    case LONG -> needJ[l] = true;
                    case FLOAT -> needF[l] = true;
                    case DOUBLE -> needD[l] = true;
                    case REFERENCE -> needL[l] = true;
                    default -> {}
                }
            }
        }
        for (AbstractInsnNode insn : mn.instructions) {
            if (insn instanceof VarInsnNode vi) {
                switch (vi.getOpcode()) {
                    case ILOAD, ISTORE -> needI[vi.var] = true;
                    case LLOAD, LSTORE -> needJ[vi.var] = true;
                    case FLOAD, FSTORE -> needF[vi.var] = true;
                    case DLOAD, DSTORE -> needD[vi.var] = true;
                    case ALOAD, ASTORE -> needL[vi.var] = true;
                }
            } else if (insn instanceof IincInsnNode inc) {
                needI[inc.var] = true;
            }
        }

        for (int l = 0; l < needI.length; l++) {
            if (needI[l]) sb.append("    int32_t l").append(l).append("_i = 0;\n");
            if (needJ[l]) sb.append("    int64_t l").append(l).append("_j = 0;\n");
            if (needF[l]) sb.append("    float l").append(l).append("_f = 0.0f;\n");
            if (needD[l]) sb.append("    double l").append(l).append("_d = 0.0;\n");
            if (needL[l]) sb.append("    int32_t l").append(l).append("_l = -1;\n");
        }

        int stackCap = Math.max(4, mn.maxStack + 4);
        for (int s = 0; s < stackCap; s++) {
            sb.append("    int32_t s").append(s).append("_i = 0; int64_t s").append(s)
              .append("_j = 0; float s").append(s).append("_f = 0.0f; double s").append(s)
              .append("_d = 0.0; int32_t s").append(s).append("_l = -1;\n");
        }

        // Bind parameters to local slots
        if (!isStatic) {
            sb.append("    l0_l = _refs.track(_self_cls, false);\n");
        }
        paramSlot = isStatic ? 0 : 1;
        for (int i = 0; i < args.length; i++) {
            Type a = args[i];
            switch (a.getSort()) {
                case Type.BOOLEAN -> sb.append("    l").append(paramSlot).append("_i = (_p").append(i).append(" ? 1 : 0);\n");
                case Type.BYTE, Type.CHAR, Type.SHORT, Type.INT ->
                        sb.append("    l").append(paramSlot).append("_i = (int32_t)_p").append(i).append(";\n");
                case Type.LONG -> sb.append("    l").append(paramSlot).append("_j = (int64_t)_p").append(i).append(";\n");
                case Type.FLOAT -> sb.append("    l").append(paramSlot).append("_f = (float)_p").append(i).append(";\n");
                case Type.DOUBLE -> sb.append("    l").append(paramSlot).append("_d = (double)_p").append(i).append(";\n");
                default -> sb.append("    l").append(paramSlot).append("_l = _refs.track(_p").append(i).append(", false);\n");
            }
            paramSlot += a.getSize();
        }

        if (cfg.blocks.isEmpty()) {
            sb.append("    return").append(defaultRetExpr(retType)).append(";\n}\n");
            return sb.toString();
        }

        int stateMask = rng.nextInt() | 1;
        int entryState = cfg.blocks.get(0).stateId ^ stateMask;
        sb.append("    uint32_t _st = (uint32_t)").append(crypto.mbaConst32(entryState, strong)).append(";\n");
        sb.append("    uint32_t _sm = (uint32_t)").append(crypto.mbaConst32(stateMask, strong)).append(";\n");

        // Prepare shuffled blocks + adaptive bogus decoy blocks (prevents huge-method explosion while stopping short-method folding)
        List<ControlFlowGraph.BasicBlock> shuffled = new ArrayList<>(cfg.blocks);
        if (strong) Collections.shuffle(shuffled, rng);

        List<Integer> bogusStates = new ArrayList<>();
        boolean emitBogus = useBogus && cfg.blocks.size() <= 250;
        if (emitBogus) {
            int bogusCount = cfg.blocks.size() <= 80
                    ? Math.min(4, Math.max(2, cfg.blocks.size() / 4))
                    : 1;
            Set<Integer> used = new HashSet<>();
            for (ControlFlowGraph.BasicBlock bb : cfg.blocks) used.add(bb.stateId);
            for (int b = 0; b < bogusCount; b++) {
                int bs;
                do { bs = rng.nextInt() | 1; } while (!used.add(bs) || bs == 0);
                bogusStates.add(bs);
            }
        }

        // Force an entry opaque transition on short STRONG methods so GCC -O2 cannot eliminate the state dispatcher
        if (emitBogus && !bogusStates.isEmpty() && cfg.blocks.size() <= 6) {
            int bogusEntry = bogusStates.get(rng.nextInt(bogusStates.size()));
            sb.append("    if (!").append(crypto.opaqueAlwaysTrue()).append(") { _st = (uint32_t)")
              .append(crypto.mbaConst32(bogusEntry ^ stateMask, strong)).append("; }\n");
        }

        sb.append("    for (;;) {\n");
        sb.append("        switch (_st ^ _sm) {\n");

        InsnList insns = mn.instructions;
        for (int idx = 0; idx < shuffled.size(); idx++) {
            ControlFlowGraph.BasicBlock bb = shuffled.get(idx);
            int origBbIdx = bb.id;
            sb.append("            case ").append(CryptoEngine.hex32(bb.stateId)).append("u: {\n");

            if (emitBogus && !bogusStates.isEmpty() && (cfg.blocks.size() <= 4 || rng.nextInt(4) == 0)) {
                int bogusTarget = bogusStates.get(rng.nextInt(bogusStates.size()));
                sb.append("                if (!").append(crypto.opaqueAlwaysTrue()).append(") { _st = (uint32_t)")
                  .append(crypto.mbaConst32(bogusTarget ^ stateMask, strong)).append("; break; }\n");
            }

            boolean terminated = false;
            for (int ii = bb.startInsn; ii <= bb.endInsn; ii++) {
                if (frames[ii] == null) continue;
                AbstractInsnNode insn = insns.get(ii);
                int op = insn.getOpcode();
                if (op < 0) continue;

                Frame<FrameAnalyzer.TypedValue> f = frames[ii];
                int top = f.getStackSize() - 1;
                boolean isTerm = emitInsn(
                        sb, ownerInternal, insn, op, f, top, cfg, bb,
                        needL, mixinCtx, pool, crypto, strong, stateMask, retType, bogusStates, rng
                );
                if (isTerm) {
                    terminated = true;
                }
            }

            if (!terminated) {
                if (origBbIdx + 1 < cfg.blocks.size()) {
                    int nextSid = cfg.blocks.get(origBbIdx + 1).stateId ^ stateMask;
                    sb.append("                _st = (uint32_t)").append(crypto.mbaConst32(nextSid, strong)).append(";\n");
                    sb.append("                break;\n");
                } else {
                    sb.append("                return").append(defaultRetExpr(retType)).append(";\n");
                }
            }
            sb.append("            }\n");
        }

        // Emit plausible decoy bogus blocks that never execute at runtime
        for (int bIdx = 0; bIdx < bogusStates.size(); bIdx++) {
            int bs = bogusStates.get(bIdx);
            int nextReal = cfg.blocks.get(rng.nextInt(cfg.blocks.size())).stateId ^ stateMask;
            sb.append("            case ").append(CryptoEngine.hex32(bs)).append("u: {\n");
            sb.append("                uint32_t _bog = (uint32_t)(_op ^ ").append(CryptoEngine.hex32(rng.nextInt())).append("u);\n");
            sb.append("                _op ^= (uint64_t)(_bog * 0x45d9f3bu);\n");
            sb.append("                _st = (uint32_t)").append(crypto.mbaConst32(nextReal, strong)).append(";\n");
            sb.append("                break;\n");
            sb.append("            }\n");
        }

        sb.append("            default: return").append(defaultRetExpr(retType)).append(";\n");
        sb.append("        }\n");
        sb.append("    }\n");
        sb.append("}\n\n");
        return sb.toString();
    }

    private static boolean emitInsn(
            StringBuilder sb,
            String ownerInternal,
            AbstractInsnNode insn,
            int op,
            Frame<FrameAnalyzer.TypedValue> f,
            int top,
            ControlFlowGraph cfg,
            ControlFlowGraph.BasicBlock bb,
            boolean[] needL,
            MixinOutliner.MixinContext mixinCtx,
            SymbolPool pool,
            CryptoEngine crypto,
            boolean strong,
            int stateMask,
            Type retType,
            List<Integer> bogusStates,
            Random rng) {

        String ind = "                ";
        int pushIdx = f.getStackSize(); // index where new push lands

        switch (op) {
            case NOP -> {}
            case ACONST_NULL -> sb.append(ind).append("s").append(pushIdx).append("_l = -1;\n");
            case ICONST_M1, ICONST_0, ICONST_1, ICONST_2, ICONST_3, ICONST_4, ICONST_5 ->
                    sb.append(ind).append("s").append(pushIdx).append("_i = ").append(crypto.mbaConst32(op - ICONST_0, strong)).append(";\n");
            case BIPUSH, SIPUSH ->
                    sb.append(ind).append("s").append(pushIdx).append("_i = ").append(crypto.mbaConst32(((IntInsnNode) insn).operand, strong)).append(";\n");
            case LCONST_0, LCONST_1 ->
                    sb.append(ind).append("s").append(pushIdx).append("_j = ").append(crypto.mbaConst64(op - LCONST_0, strong)).append(";\n");
            case FCONST_0, FCONST_1, FCONST_2 ->
                    sb.append(ind).append("s").append(pushIdx).append("_f = hy::bits_to_f32((uint32_t)").append(crypto.mbaConst32(Float.floatToRawIntBits((float) (op - FCONST_0)), strong)).append(");\n");
            case DCONST_0, DCONST_1 ->
                    sb.append(ind).append("s").append(pushIdx).append("_d = hy::bits_to_f64((uint64_t)").append(crypto.mbaConst64(Double.doubleToRawLongBits((double) (op - DCONST_0)), strong)).append(");\n");

            case LDC -> {
                Object cst = ((LdcInsnNode) insn).cst;
                if (cst instanceof Integer v) {
                    sb.append(ind).append("s").append(pushIdx).append("_i = ").append(crypto.mbaConst32(v, strong)).append(";\n");
                } else if (cst instanceof Long v) {
                    sb.append(ind).append("s").append(pushIdx).append("_j = ").append(crypto.mbaConst64(v, strong)).append(";\n");
                } else if (cst instanceof Float v) {
                    sb.append(ind).append("s").append(pushIdx).append("_f = hy::bits_to_f32((uint32_t)").append(crypto.mbaConst32(Float.floatToRawIntBits(v), strong)).append(");\n");
                } else if (cst instanceof Double v) {
                    sb.append(ind).append("s").append(pushIdx).append("_d = hy::bits_to_f64((uint64_t)").append(crypto.mbaConst64(Double.doubleToRawLongBits(v), strong)).append(");\n");
                } else if (cst instanceof String s) {
                    int wid = pool.internWStr(s);
                    sb.append(ind).append("s").append(pushIdx).append("_l = _refs.track((jobject)hy::new_wstr(env, ").append(crypto.mbaConst32(wid, strong)).append("), true);\n");
                    emitExCheck(sb, f.getStackSize() + 1, f, cfg, bb, pool, crypto, strong, stateMask, retType);
                } else if (cst instanceof Type t) {
                    if (t.getSort() == Type.OBJECT || t.getSort() == Type.ARRAY) {
                        int cid = pool.internClass(t.getInternalName());
                        sb.append(ind).append("s").append(pushIdx).append("_l = _refs.track((jobject)hy::resolve_class(env, ").append(crypto.mbaConst32(cid, strong)).append("), false);\n");
                        emitExCheck(sb, f.getStackSize() + 1, f, cfg, bb, pool, crypto, strong, stateMask, retType);
                    } else {
                        sb.append(ind).append("s").append(pushIdx).append("_l = _refs.track((jobject)hy::resolve_prim_class(env, ").append(VmCompiler.typeToKind(t)).append("), true);\n");
                    }
                } else {
                    throw new UnsupportedOperationException("Unsupported LDC: " + cst.getClass());
                }
            }

            case ILOAD -> sb.append(ind).append("s").append(pushIdx).append("_i = l").append(((VarInsnNode) insn).var).append("_i;\n");
            case LLOAD -> sb.append(ind).append("s").append(pushIdx).append("_j = l").append(((VarInsnNode) insn).var).append("_j;\n");
            case FLOAD -> sb.append(ind).append("s").append(pushIdx).append("_f = l").append(((VarInsnNode) insn).var).append("_f;\n");
            case DLOAD -> sb.append(ind).append("s").append(pushIdx).append("_d = l").append(((VarInsnNode) insn).var).append("_d;\n");
            case ALOAD -> {
                int lv = ((VarInsnNode) insn).var;
                sb.append(ind).append("s").append(pushIdx).append("_l = _refs.retain(l").append(lv).append("_l);\n");
            }

            case ISTORE, LSTORE, FSTORE, DSTORE -> {
                int lv = ((VarInsnNode) insn).var;
                String suf = switch (op) { case ISTORE -> "_i"; case LSTORE -> "_j"; case FSTORE -> "_f"; default -> "_d"; };
                if (needL[lv]) {
                    sb.append(ind).append("if (l").append(lv).append("_l >= 0) { _refs.release(l").append(lv).append("_l); l").append(lv).append("_l = -1; }\n");
                }
                sb.append(ind).append("l").append(lv).append(suf).append(" = s").append(top).append(suf).append(";\n");
            }
            case ASTORE -> {
                int lv = ((VarInsnNode) insn).var;
                sb.append(ind).append("if (l").append(lv).append("_l != s").append(top).append("_l) { _refs.release(l").append(lv)
                  .append("_l); l").append(lv).append("_l = s").append(top).append("_l; } else { _refs.release(s").append(top)
                  .append("_l); } s").append(top).append("_l = -1;\n");
            }
            case IINC -> {
                IincInsnNode inc = (IincInsnNode) insn;
                sb.append(ind).append("l").append(inc.var).append("_i = (int32_t)((uint32_t)l").append(inc.var)
                  .append("_i + (uint32_t)").append(crypto.mbaConst32(inc.incr, strong)).append(");\n");
            }

            case POP -> {
                if (f.getStack(top).kind == FrameAnalyzer.Kind.REFERENCE) {
                    sb.append(ind).append("_refs.release(s").append(top).append("_l); s").append(top).append("_l = -1;\n");
                }
            }
            case POP2 -> {
                FrameAnalyzer.TypedValue v1 = f.getStack(top);
                if (v1.getSize() == 1) {
                    if (v1.kind == FrameAnalyzer.Kind.REFERENCE) {
                        sb.append(ind).append("_refs.release(s").append(top).append("_l); s").append(top).append("_l = -1;\n");
                    }
                    FrameAnalyzer.TypedValue v2 = f.getStack(top - 1);
                    if (v2.kind == FrameAnalyzer.Kind.REFERENCE) {
                        sb.append(ind).append("_refs.release(s").append(top - 1).append("_l); s").append(top - 1).append("_l = -1;\n");
                    }
                }
            }
            case DUP -> emitDupSlot(sb, ind, top + 1, top, f.getStack(top));
            case DUP_X1 -> {
                FrameAnalyzer.TypedValue v1 = f.getStack(top);
                FrameAnalyzer.TypedValue v2 = f.getStack(top - 1);
                emitMoveSlot(sb, ind, top + 1, top, v1);
                emitMoveSlot(sb, ind, top, top - 1, v2);
                emitDupSlot(sb, ind, top - 1, top + 1, v1);
            }
            case DUP_X2 -> {
                FrameAnalyzer.TypedValue v1 = f.getStack(top);
                FrameAnalyzer.TypedValue v2 = f.getStack(top - 1);
                if (v2.getSize() == 2) {
                    emitMoveSlot(sb, ind, top + 1, top, v1);
                    emitMoveSlot(sb, ind, top, top - 1, v2);
                    emitDupSlot(sb, ind, top - 1, top + 1, v1);
                } else {
                    FrameAnalyzer.TypedValue v3 = f.getStack(top - 2);
                    emitMoveSlot(sb, ind, top + 1, top, v1);
                    emitMoveSlot(sb, ind, top, top - 1, v2);
                    emitMoveSlot(sb, ind, top - 1, top - 2, v3);
                    emitDupSlot(sb, ind, top - 2, top + 1, v1);
                }
            }
            case DUP2 -> {
                FrameAnalyzer.TypedValue v1 = f.getStack(top);
                if (v1.getSize() == 2) {
                    emitDupSlot(sb, ind, top + 1, top, v1);
                } else {
                    FrameAnalyzer.TypedValue v2 = f.getStack(top - 1);
                    emitDupSlot(sb, ind, top + 1, top - 1, v2);
                    emitDupSlot(sb, ind, top + 2, top, v1);
                }
            }
            case DUP2_X1 -> {
                FrameAnalyzer.TypedValue v1 = f.getStack(top);
                FrameAnalyzer.TypedValue v2 = f.getStack(top - 1);
                if (v1.getSize() == 2) {
                    emitMoveSlot(sb, ind, top + 1, top, v1);
                    emitMoveSlot(sb, ind, top, top - 1, v2);
                    emitDupSlot(sb, ind, top - 1, top + 1, v1);
                } else {
                    FrameAnalyzer.TypedValue v3 = f.getStack(top - 2);
                    emitMoveSlot(sb, ind, top + 2, top, v1);
                    emitMoveSlot(sb, ind, top + 1, top - 1, v2);
                    emitMoveSlot(sb, ind, top, top - 2, v3);
                    emitDupSlot(sb, ind, top - 2, top + 1, v2);
                    emitDupSlot(sb, ind, top - 1, top + 2, v1);
                }
            }
            case DUP2_X2 -> {
                FrameAnalyzer.TypedValue v1 = f.getStack(top);
                FrameAnalyzer.TypedValue v2 = f.getStack(top - 1);
                if (v1.getSize() == 2 && v2.getSize() == 2) {
                    emitMoveSlot(sb, ind, top + 1, top, v1);
                    emitMoveSlot(sb, ind, top, top - 1, v2);
                    emitDupSlot(sb, ind, top - 1, top + 1, v1);
                } else if (v1.getSize() == 2) {
                    FrameAnalyzer.TypedValue v3 = f.getStack(top - 2);
                    emitMoveSlot(sb, ind, top + 1, top, v1);
                    emitMoveSlot(sb, ind, top, top - 1, v2);
                    emitMoveSlot(sb, ind, top - 1, top - 2, v3);
                    emitDupSlot(sb, ind, top - 2, top + 1, v1);
                } else {
                    FrameAnalyzer.TypedValue v3 = f.getStack(top - 2);
                    if (v3.getSize() == 2) {
                        emitMoveSlot(sb, ind, top + 2, top, v1);
                        emitMoveSlot(sb, ind, top + 1, top - 1, v2);
                        emitMoveSlot(sb, ind, top, top - 2, v3);
                        emitDupSlot(sb, ind, top - 2, top + 1, v2);
                        emitDupSlot(sb, ind, top - 1, top + 2, v1);
                    } else {
                        FrameAnalyzer.TypedValue v4 = f.getStack(top - 3);
                        emitMoveSlot(sb, ind, top + 2, top, v1);
                        emitMoveSlot(sb, ind, top + 1, top - 1, v2);
                        emitMoveSlot(sb, ind, top, top - 2, v3);
                        emitMoveSlot(sb, ind, top - 1, top - 3, v4);
                        emitDupSlot(sb, ind, top - 3, top + 1, v2);
                        emitDupSlot(sb, ind, top - 2, top + 2, v1);
                    }
                }
            }
            case SWAP -> {
                FrameAnalyzer.TypedValue v1 = f.getStack(top);
                FrameAnalyzer.TypedValue v2 = f.getStack(top - 1);
                emitMoveSlot(sb, ind, top + 1, top, v1);
                emitMoveSlot(sb, ind, top, top - 1, v2);
                emitMoveSlot(sb, ind, top - 1, top + 1, v1);
            }

            // Integer math (overflow-safe unsigned arithmetic + MBA anchored to _op in STRONG/ULTRA)
            case IADD -> {
                String a = "s" + (top - 1) + "_i", b = "s" + top + "_i";
                if (strong) {
                    String z = "(uint32_t)((((_op * (_op + 1ULL)) & 1ULL) != 0ULL) ? " + CryptoEngine.hex32(rng.nextInt()) + "u : 0u)";
                    sb.append(ind).append(a).append(" = (int32_t)((((uint32_t)").append(a).append(" ^ (uint32_t)").append(b)
                      .append(") + (((uint32_t)").append(a).append(" & (uint32_t)").append(b).append(") << 1)) ^ ").append(z).append(");\n");
                } else {
                    sb.append(ind).append(a).append(" = (int32_t)((uint32_t)").append(a).append(" + (uint32_t)").append(b).append(");\n");
                }
            }
            case ISUB -> {
                String a = "s" + (top - 1) + "_i", b = "s" + top + "_i";
                if (strong) {
                    String z = "(uint32_t)((((_op * (_op + 1ULL)) & 1ULL) != 0ULL) ? " + CryptoEngine.hex32(rng.nextInt()) + "u : 0u)";
                    sb.append(ind).append(a).append(" = (int32_t)((((uint32_t)").append(a).append(" ^ (uint32_t)").append(b)
                      .append(") - ((~(uint32_t)").append(a).append(" & (uint32_t)").append(b).append(") << 1)) ^ ").append(z).append(");\n");
                } else {
                    sb.append(ind).append(a).append(" = (int32_t)((uint32_t)").append(a).append(" - (uint32_t)").append(b).append(");\n");
                }
            }
            case IMUL -> {
                String a = "s" + (top - 1) + "_i", b = "s" + top + "_i";
                if (strong) {
                    String z = "(uint32_t)((((_op * (_op + 1ULL)) & 1ULL) != 0ULL) ? " + CryptoEngine.hex32(rng.nextInt() | 1) + "u : 0u)";
                    sb.append(ind).append(a).append(" = (int32_t)(((uint32_t)").append(a).append(" ^ ").append(z)
                      .append(") * ((uint32_t)").append(b).append(" ^ ").append(z).append("));\n");
                } else {
                    sb.append(ind).append(a).append(" = (int32_t)((uint32_t)").append(a).append(" * (uint32_t)").append(b).append(");\n");
                }
            }
            case IDIV -> {
                sb.append(ind).append("if (s").append(top).append("_i == 0) { hy::throw_arith(env); ");
                emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(" } else { s").append(top - 1).append("_i = hy::j_idiv(s").append(top - 1).append("_i, s").append(top).append("_i); }\n");
            }
            case IREM -> {
                sb.append(ind).append("if (s").append(top).append("_i == 0) { hy::throw_arith(env); ");
                emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(" } else { s").append(top - 1).append("_i = hy::j_irem(s").append(top - 1).append("_i, s").append(top).append("_i); }\n");
            }
            case INEG -> sb.append(ind).append("s").append(top).append("_i = (int32_t)(0u - (uint32_t)s").append(top).append("_i);\n");
            case ISHL -> sb.append(ind).append("s").append(top - 1).append("_i = (int32_t)((uint32_t)s").append(top - 1).append("_i << (s").append(top).append("_i & 31));\n");
            case ISHR -> sb.append(ind).append("s").append(top - 1).append("_i = (s").append(top - 1).append("_i >> (s").append(top).append("_i & 31));\n");
            case IUSHR -> sb.append(ind).append("s").append(top - 1).append("_i = (int32_t)((uint32_t)s").append(top - 1).append("_i >> (s").append(top).append("_i & 31));\n");
            case IAND -> sb.append(ind).append("s").append(top - 1).append("_i &= s").append(top).append("_i;\n");
            case IOR -> sb.append(ind).append("s").append(top - 1).append("_i |= s").append(top).append("_i;\n");
            case IXOR -> {
                String a = "s" + (top - 1) + "_i", b = "s" + top + "_i";
                if (strong) {
                    sb.append(ind).append(a).append(" = (int32_t)(((uint32_t)").append(a).append(" | (uint32_t)").append(b)
                      .append(") - ((uint32_t)").append(a).append(" & (uint32_t)").append(b).append("));\n");
                } else {
                    sb.append(ind).append(a).append(" ^= ").append(b).append(";\n");
                }
            }

            // Long math
            case LADD -> sb.append(ind).append("s").append(top - 1).append("_j = (int64_t)((uint64_t)s").append(top - 1).append("_j + (uint64_t)s").append(top).append("_j);\n");
            case LSUB -> sb.append(ind).append("s").append(top - 1).append("_j = (int64_t)((uint64_t)s").append(top - 1).append("_j - (uint64_t)s").append(top).append("_j);\n");
            case LMUL -> sb.append(ind).append("s").append(top - 1).append("_j = (int64_t)((uint64_t)s").append(top - 1).append("_j * (uint64_t)s").append(top).append("_j);\n");
            case LDIV -> {
                sb.append(ind).append("if (s").append(top).append("_j == 0) { hy::throw_arith(env); ");
                emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(" } else { s").append(top - 1).append("_j = hy::j_ldiv(s").append(top - 1).append("_j, s").append(top).append("_j); }\n");
            }
            case LREM -> {
                sb.append(ind).append("if (s").append(top).append("_j == 0) { hy::throw_arith(env); ");
                emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(" } else { s").append(top - 1).append("_j = hy::j_lrem(s").append(top - 1).append("_j, s").append(top).append("_j); }\n");
            }
            case LNEG -> sb.append(ind).append("s").append(top).append("_j = (int64_t)(0ULL - (uint64_t)s").append(top).append("_j);\n");
            case LSHL -> sb.append(ind).append("s").append(top - 1).append("_j = (int64_t)((uint64_t)s").append(top - 1).append("_j << (s").append(top).append("_i & 63));\n");
            case LSHR -> sb.append(ind).append("s").append(top - 1).append("_j = (s").append(top - 1).append("_j >> (s").append(top).append("_i & 63));\n");
            case LUSHR -> sb.append(ind).append("s").append(top - 1).append("_j = (int64_t)((uint64_t)s").append(top - 1).append("_j >> (s").append(top).append("_i & 63));\n");
            case LAND -> sb.append(ind).append("s").append(top - 1).append("_j &= s").append(top).append("_j;\n");
            case LOR -> sb.append(ind).append("s").append(top - 1).append("_j |= s").append(top).append("_j;\n");
            case LXOR -> sb.append(ind).append("s").append(top - 1).append("_j ^= s").append(top).append("_j;\n");

            // Float & Double math
            case FADD -> sb.append(ind).append("s").append(top - 1).append("_f += s").append(top).append("_f;\n");
            case FSUB -> sb.append(ind).append("s").append(top - 1).append("_f -= s").append(top).append("_f;\n");
            case FMUL -> sb.append(ind).append("s").append(top - 1).append("_f *= s").append(top).append("_f;\n");
            case FDIV -> sb.append(ind).append("s").append(top - 1).append("_f /= s").append(top).append("_f;\n");
            case FREM -> sb.append(ind).append("s").append(top - 1).append("_f = hy::j_frem(s").append(top - 1).append("_f, s").append(top).append("_f);\n");
            case FNEG -> sb.append(ind).append("s").append(top).append("_f = -s").append(top).append("_f;\n");

            case DADD -> sb.append(ind).append("s").append(top - 1).append("_d += s").append(top).append("_d;\n");
            case DSUB -> sb.append(ind).append("s").append(top - 1).append("_d -= s").append(top).append("_d;\n");
            case DMUL -> sb.append(ind).append("s").append(top - 1).append("_d *= s").append(top).append("_d;\n");
            case DDIV -> sb.append(ind).append("s").append(top - 1).append("_d /= s").append(top).append("_d;\n");
            case DREM -> sb.append(ind).append("s").append(top - 1).append("_d = hy::j_drem(s").append(top - 1).append("_d, s").append(top).append("_d);\n");
            case DNEG -> sb.append(ind).append("s").append(top).append("_d = -s").append(top).append("_d;\n");

            // Conversions
            case I2L -> sb.append(ind).append("s").append(top).append("_j = (int64_t)s").append(top).append("_i;\n");
            case I2F -> sb.append(ind).append("s").append(top).append("_f = (float)s").append(top).append("_i;\n");
            case I2D -> sb.append(ind).append("s").append(top).append("_d = (double)s").append(top).append("_i;\n");
            case L2I -> sb.append(ind).append("s").append(top).append("_i = (int32_t)s").append(top).append("_j;\n");
            case L2F -> sb.append(ind).append("s").append(top).append("_f = (float)s").append(top).append("_j;\n");
            case L2D -> sb.append(ind).append("s").append(top).append("_d = (double)s").append(top).append("_j;\n");
            case F2I -> sb.append(ind).append("s").append(top).append("_i = hy::j_f2i(s").append(top).append("_f);\n");
            case F2L -> sb.append(ind).append("s").append(top).append("_j = hy::j_f2l(s").append(top).append("_f);\n");
            case F2D -> sb.append(ind).append("s").append(top).append("_d = (double)s").append(top).append("_f;\n");
            case D2I -> sb.append(ind).append("s").append(top).append("_i = hy::j_d2i(s").append(top).append("_d);\n");
            case D2L -> sb.append(ind).append("s").append(top).append("_j = hy::j_d2l(s").append(top).append("_d);\n");
            case D2F -> sb.append(ind).append("s").append(top).append("_f = (float)s").append(top).append("_d;\n");
            case I2B -> sb.append(ind).append("s").append(top).append("_i = (int32_t)(int8_t)s").append(top).append("_i;\n");
            case I2C -> sb.append(ind).append("s").append(top).append("_i = (int32_t)(uint16_t)s").append(top).append("_i;\n");
            case I2S -> sb.append(ind).append("s").append(top).append("_i = (int32_t)(int16_t)s").append(top).append("_i;\n");

            case LCMP -> sb.append(ind).append("s").append(top - 1).append("_i = (s").append(top - 1).append("_j > s").append(top).append("_j) ? 1 : ((s").append(top - 1).append("_j < s").append(top).append("_j) ? -1 : 0);\n");
            case FCMPL -> sb.append(ind).append("s").append(top - 1).append("_i = hy::j_fcmpl(s").append(top - 1).append("_f, s").append(top).append("_f);\n");
            case FCMPG -> sb.append(ind).append("s").append(top - 1).append("_i = hy::j_fcmpg(s").append(top - 1).append("_f, s").append(top).append("_f);\n");
            case DCMPL -> sb.append(ind).append("s").append(top - 1).append("_i = hy::j_dcmpl(s").append(top - 1).append("_d, s").append(top).append("_d);\n");
            case DCMPG -> sb.append(ind).append("s").append(top - 1).append("_i = hy::j_dcmpg(s").append(top - 1).append("_d, s").append(top).append("_d);\n");

            // Branches & Switches (CFF State transitions)
            case GOTO -> {
                ControlFlowGraph.BasicBlock target = cfg.labelToBlock.get(((JumpInsnNode) insn).label);
                sb.append(ind).append("_st = (uint32_t)").append(crypto.mbaConst32(target.stateId ^ stateMask, strong)).append(";\n");
                sb.append(ind).append("break;\n");
                return true;
            }
            case IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE,
                 IF_ICMPEQ, IF_ICMPNE, IF_ICMPLT, IF_ICMPGE, IF_ICMPGT, IF_ICMPLE,
                 IF_ACMPEQ, IF_ACMPNE, IFNULL, IFNONNULL -> {
                ControlFlowGraph.BasicBlock taken = cfg.labelToBlock.get(((JumpInsnNode) insn).label);
                ControlFlowGraph.BasicBlock fall = cfg.blocks.get(bb.id + 1);
                String cond = switch (op) {
                    case IFEQ -> "s" + top + "_i == 0";
                    case IFNE -> "s" + top + "_i != 0";
                    case IFLT -> "s" + top + "_i < 0";
                    case IFGE -> "s" + top + "_i >= 0";
                    case IFGT -> "s" + top + "_i > 0";
                    case IFLE -> "s" + top + "_i <= 0";
                    case IF_ICMPEQ -> "s" + (top - 1) + "_i == s" + top + "_i";
                    case IF_ICMPNE -> "s" + (top - 1) + "_i != s" + top + "_i";
                    case IF_ICMPLT -> "s" + (top - 1) + "_i < s" + top + "_i";
                    case IF_ICMPGE -> "s" + (top - 1) + "_i >= s" + top + "_i";
                    case IF_ICMPGT -> "s" + (top - 1) + "_i > s" + top + "_i";
                    case IF_ICMPLE -> "s" + (top - 1) + "_i <= s" + top + "_i";
                    case IF_ACMPEQ -> "env->IsSameObject(_refs.raw(s" + (top - 1) + "_l), _refs.raw(s" + top + "_l))";
                    case IF_ACMPNE -> "!env->IsSameObject(_refs.raw(s" + (top - 1) + "_l), _refs.raw(s" + top + "_l))";
                    case IFNULL -> "_refs.raw(s" + top + "_l) == nullptr";
                    default -> "_refs.raw(s" + top + "_l) != nullptr";
                };
                sb.append(ind).append("{\n");
                sb.append(ind).append("    uint32_t _cond = (").append(cond).append(") ? 1u : 0u;\n");
                // Release consumed ref operands AFTER IsSameObject/null check!
                if (op == IF_ACMPEQ || op == IF_ACMPNE) {
                    sb.append(ind).append("    _refs.release(s").append(top).append("_l); s").append(top).append("_l = -1;\n");
                    sb.append(ind).append("    _refs.release(s").append(top - 1).append("_l); s").append(top - 1).append("_l = -1;\n");
                } else if (op == IFNULL || op == IFNONNULL) {
                    sb.append(ind).append("    _refs.release(s").append(top).append("_l); s").append(top).append("_l = -1;\n");
                }
                int tEnc = taken.stateId ^ stateMask;
                int fEnc = fall.stateId ^ stateMask;
                sb.append(ind).append("    _st = _cond ? (uint32_t)").append(crypto.mbaConst32(tEnc, strong))
                  .append(" : (uint32_t)").append(crypto.mbaConst32(fEnc, strong)).append(";\n");
                sb.append(ind).append("    break;\n");
                sb.append(ind).append("}\n");
                return true;
            }
            case TABLESWITCH -> {
                TableSwitchInsnNode ts = (TableSwitchInsnNode) insn;
                sb.append(ind).append("switch (s").append(top).append("_i) {\n");
                for (int k = 0; k < ts.labels.size(); k++) {
                    int val = ts.min + k;
                    ControlFlowGraph.BasicBlock target = cfg.labelToBlock.get(ts.labels.get(k));
                    sb.append(ind).append("    case ").append(val).append(": _st = (uint32_t)")
                      .append(crypto.mbaConst32(target.stateId ^ stateMask, strong)).append("; break;\n");
                }
                ControlFlowGraph.BasicBlock dflt = cfg.labelToBlock.get(ts.dflt);
                sb.append(ind).append("    default: _st = (uint32_t)")
                  .append(crypto.mbaConst32(dflt.stateId ^ stateMask, strong)).append("; break;\n");
                sb.append(ind).append("}\n").append(ind).append("break;\n");
                return true;
            }
            case LOOKUPSWITCH -> {
                LookupSwitchInsnNode ls = (LookupSwitchInsnNode) insn;
                sb.append(ind).append("switch (s").append(top).append("_i) {\n");
                for (int k = 0; k < ls.keys.size(); k++) {
                    ControlFlowGraph.BasicBlock target = cfg.labelToBlock.get(ls.labels.get(k));
                    sb.append(ind).append("    case ").append(ls.keys.get(k)).append(": _st = (uint32_t)")
                      .append(crypto.mbaConst32(target.stateId ^ stateMask, strong)).append("; break;\n");
                }
                ControlFlowGraph.BasicBlock dflt = cfg.labelToBlock.get(ls.dflt);
                sb.append(ind).append("    default: _st = (uint32_t)")
                  .append(crypto.mbaConst32(dflt.stateId ^ stateMask, strong)).append("; break;\n");
                sb.append(ind).append("}\n").append(ind).append("break;\n");
                return true;
            }

            // Fields (including Mixin @Shadow resolution)
            case GETSTATIC, PUTSTATIC, GETFIELD, PUTFIELD -> {
                FieldInsnNode fi = (FieldInsnNode) insn;
                boolean isStaticField = (op == GETSTATIC || op == PUTSTATIC);
                Type ft = Type.getType(fi.desc);
                String targetOwner = resolveFieldOwner(fi, mixinCtx);
                boolean dynamicInstanceShadow = mixinCtx != null && !isStaticField
                        && fi.owner.equals(mixinCtx.mixinInternalName)
                        && !mixinCtx.declaredMembers.contains("F:" + fi.name + ":" + fi.desc)
                        && mixinCtx.targets.size() != 1;

                if (op == GETSTATIC) {
                    int fid = pool.internField(targetOwner, fi.name, fi.desc, true);
                    emitGetField(sb, ind, pushIdx, ft, true, "hy::resolve_class(env, " + crypto.mbaConst32(pool.internClass(targetOwner), strong) + ")",
                            "hy::resolve_sfield(env, " + crypto.mbaConst32(fid, strong) + ")", f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                } else if (op == PUTSTATIC) {
                    int fid = pool.internField(targetOwner, fi.name, fi.desc, true);
                    emitPutField(sb, ind, top, ft, true, "hy::resolve_class(env, " + crypto.mbaConst32(pool.internClass(targetOwner), strong) + ")",
                            "hy::resolve_sfield(env, " + crypto.mbaConst32(fid, strong) + ")", f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                } else if (op == GETFIELD) {
                    int objSlot = top;
                    sb.append(ind).append("{\n");
                    String ind2 = ind + "    ";
                    sb.append(ind2).append("jobject _obj = _refs.raw(s").append(objSlot).append("_l);\n");
                    sb.append(ind2).append("if (!_obj) { hy::throw_npe(env); ");
                    emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                    sb.append(" }\n");
                    String fidExpr;
                    if (dynamicInstanceShadow) {
                        int nameSid = pool.internSym(fi.name);
                        int descSid = pool.internSym(fi.desc);
                        fidExpr = "hy::resolve_dyn_field(env, _obj, " + crypto.mbaConst32(nameSid, strong) + ", " + crypto.mbaConst32(descSid, strong) + ")";
                    } else {
                        int fid = pool.internField(targetOwner, fi.name, fi.desc, false);
                        fidExpr = "hy::resolve_ifield(env, " + crypto.mbaConst32(fid, strong) + ")";
                    }
                    sb.append(ind2).append("jfieldID _fid = ").append(fidExpr).append(";\n");
                    emitExCheck(sb, f.getStackSize(), f, cfg, bb, pool, crypto, strong, stateMask, retType);
                    emitReadInstanceField(sb, ind2, top, ft, "_obj", "_fid");
                    sb.append(ind2).append("_refs.release(s").append(objSlot).append("_l); ");
                    if (ft.getSort() != Type.OBJECT && ft.getSort() != Type.ARRAY) {
                        sb.append("s").append(objSlot).append("_l = -1;\n");
                    } else {
                        sb.append("s").append(top).append("_l = _tmp_res;\n");
                    }
                    sb.append(ind).append("}\n");
                } else { // PUTFIELD
                    int objSlot = top - 1;
                    int valSlot = top;
                    sb.append(ind).append("{\n");
                    String ind2 = ind + "    ";
                    sb.append(ind2).append("jobject _obj = _refs.raw(s").append(objSlot).append("_l);\n");
                    sb.append(ind2).append("if (!_obj) { hy::throw_npe(env); ");
                    emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                    sb.append(" }\n");
                    String fidExpr;
                    if (dynamicInstanceShadow) {
                        int nameSid = pool.internSym(fi.name);
                        int descSid = pool.internSym(fi.desc);
                        fidExpr = "hy::resolve_dyn_field(env, _obj, " + crypto.mbaConst32(nameSid, strong) + ", " + crypto.mbaConst32(descSid, strong) + ")";
                    } else {
                        int fid = pool.internField(targetOwner, fi.name, fi.desc, false);
                        fidExpr = "hy::resolve_ifield(env, " + crypto.mbaConst32(fid, strong) + ")";
                    }
                    sb.append(ind2).append("jfieldID _fid = ").append(fidExpr).append(";\n");
                    emitExCheck(sb, f.getStackSize(), f, cfg, bb, pool, crypto, strong, stateMask, retType);
                    emitWriteInstanceField(sb, ind2, valSlot, ft, "_obj", "_fid");
                    if (ft.getSort() == Type.OBJECT || ft.getSort() == Type.ARRAY) {
                        sb.append(ind2).append("_refs.release(s").append(valSlot).append("_l); s").append(valSlot).append("_l = -1;\n");
                    }
                    sb.append(ind2).append("_refs.release(s").append(objSlot).append("_l); s").append(objSlot).append("_l = -1;\n");
                    sb.append(ind).append("}\n");
                }
            }

            // Method calls (including Intrinsics & Mixin @Shadow / @Unique / super / constructors)
            case INVOKESTATIC, INVOKEVIRTUAL, INVOKESPECIAL, INVOKEINTERFACE -> {
                MethodInsnNode mi = (MethodInsnNode) insn;
                if (op == INVOKESTATIC && tryEmitStaticIntrinsic(sb, ind, mi, f)) {
                    break;
                }
                boolean isStaticCall = (op == INVOKESTATIC);
                Type callMt = Type.getMethodType(mi.desc);
                Type[] callArgs = callMt.getArgumentTypes();
                Type callRet = callMt.getReturnType();
                int argc = callArgs.length;
                int baseSlot = isStaticCall ? (f.getStackSize() - argc) : (f.getStackSize() - argc - 1);

                String targetOwner = resolveMethodOwner(mi, mixinCtx);
                boolean dynamicMixinCall = mixinCtx != null && !isStaticCall
                        && mi.owner.equals(mixinCtx.mixinInternalName)
                        && (mixinCtx.targets.size() != 1 || mixinCtx.declaredMembers.contains("M:" + mi.name + mi.desc));

                sb.append(ind).append("{\n");
                String ind2 = ind + "    ";
                if (!isStaticCall) {
                    sb.append(ind2).append("jobject _recv = _refs.raw(s").append(baseSlot).append("_l);\n");
                    sb.append(ind2).append("if (!_recv) { hy::throw_npe(env); ");
                    emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                    sb.append(" }\n");
                }

                String midExpr;
                if (dynamicMixinCall) {
                    int nameSid = pool.internSym(mi.name);
                    int descSid = pool.internSym(mi.desc);
                    midExpr = "hy::resolve_dyn_method(env, _recv, " + crypto.mbaConst32(nameSid, strong) + ", " + crypto.mbaConst32(descSid, strong) + ")";
                } else {
                    int mid = pool.internMethod(targetOwner, mi.name, mi.desc, isStaticCall);
                    midExpr = (isStaticCall ? "hy::resolve_smethod(env, " : "hy::resolve_imethod(env, ")
                            + crypto.mbaConst32(mid, strong) + ")";
                }

                sb.append(ind2).append("jmethodID _mid = ").append(midExpr).append(";\n");
                emitExCheck(sb, f.getStackSize(), f, cfg, bb, pool, crypto, strong, stateMask, retType);

                // Build jvalue array cleanly
                if (argc > 0) {
                    sb.append(ind2).append("jvalue _args[").append(argc).append("];\n");
                    for (int k = 0; k < argc; k++) {
                        int argSlot = isStaticCall ? (baseSlot + k) : (baseSlot + 1 + k);
                        emitPackJValue(sb, ind2, "_args[" + k + "]", argSlot, callArgs[k]);
                    }
                }
                String argsPtr = argc > 0 ? "_args" : "nullptr";

                String callTarget;
                if (isStaticCall) {
                    int clsId = pool.internClass(targetOwner);
                    sb.append(ind2).append("jclass _cls = hy::resolve_class(env, ").append(crypto.mbaConst32(clsId, strong)).append(");\n");
                    emitExCheck(sb, f.getStackSize(), f, cfg, bb, pool, crypto, strong, stateMask, retType);
                    callTarget = "CallStatic" + jniCallSuffix(callRet) + "MethodA(_cls, _mid, " + argsPtr + ")";
                } else if (op == INVOKESPECIAL) {
                    int clsId = pool.internClass(targetOwner);
                    sb.append(ind2).append("jclass _cls = hy::resolve_class(env, ").append(crypto.mbaConst32(clsId, strong)).append(");\n");
                    emitExCheck(sb, f.getStackSize(), f, cfg, bb, pool, crypto, strong, stateMask, retType);
                    callTarget = "CallNonvirtual" + jniCallSuffix(callRet) + "MethodA(_recv, _cls, _mid, " + argsPtr + ")";
                } else {
                    callTarget = "Call" + jniCallSuffix(callRet) + "MethodA(_recv, _mid, " + argsPtr + ")";
                }

                // Invoke & store temp result
                switch (callRet.getSort()) {
                    case Type.VOID -> sb.append(ind2).append("env->").append(callTarget).append(";\n");
                    case Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT ->
                            sb.append(ind2).append("int32_t _cr = (int32_t)env->").append(callTarget).append(";\n");
                    case Type.LONG -> sb.append(ind2).append("int64_t _cr = (int64_t)env->").append(callTarget).append(";\n");
                    case Type.FLOAT -> sb.append(ind2).append("float _cr = (float)env->").append(callTarget).append(";\n");
                    case Type.DOUBLE -> sb.append(ind2).append("double _cr = (double)env->").append(callTarget).append(";\n");
                    default -> sb.append(ind2).append("jobject _cr = env->").append(callTarget).append(";\n");
                }

                // Check exception BEFORE releasing args (if exception thrown, emitExCheck cleans entire stack)
                if (callRet.getSort() == Type.OBJECT || callRet.getSort() == Type.ARRAY) {
                    sb.append(ind2).append("if (env->ExceptionCheck()) [[unlikely]] { if (_cr) env->DeleteLocalRef(_cr); ");
                    emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                    sb.append(" }\n");
                } else {
                    emitExCheck(sb, f.getStackSize(), f, cfg, bb, pool, crypto, strong, stateMask, retType);
                }

                // Release receiver and object args now that call succeeded
                if (!isStaticCall) {
                    sb.append(ind2).append("_refs.release(s").append(baseSlot).append("_l); s").append(baseSlot).append("_l = -1;\n");
                }
                for (int k = 0; k < argc; k++) {
                    if (callArgs[k].getSort() == Type.OBJECT || callArgs[k].getSort() == Type.ARRAY) {
                        int argSlot = isStaticCall ? (baseSlot + k) : (baseSlot + 1 + k);
                        sb.append(ind2).append("_refs.release(s").append(argSlot).append("_l); s").append(argSlot).append("_l = -1;\n");
                    }
                }

                // Push return result at baseSlot
                switch (callRet.getSort()) {
                    case Type.VOID -> {}
                    case Type.BOOLEAN -> sb.append(ind2).append("s").append(baseSlot).append("_i = _cr ? 1 : 0;\n");
                    case Type.CHAR -> sb.append(ind2).append("s").append(baseSlot).append("_i = (int32_t)(uint16_t)_cr;\n");
                    case Type.BYTE -> sb.append(ind2).append("s").append(baseSlot).append("_i = (int32_t)(int8_t)_cr;\n");
                    case Type.SHORT -> sb.append(ind2).append("s").append(baseSlot).append("_i = (int32_t)(int16_t)_cr;\n");
                    case Type.INT -> sb.append(ind2).append("s").append(baseSlot).append("_i = _cr;\n");
                    case Type.LONG -> sb.append(ind2).append("s").append(baseSlot).append("_j = _cr;\n");
                    case Type.FLOAT -> sb.append(ind2).append("s").append(baseSlot).append("_f = _cr;\n");
                    case Type.DOUBLE -> sb.append(ind2).append("s").append(baseSlot).append("_d = _cr;\n");
                    default -> sb.append(ind2).append("s").append(baseSlot).append("_l = _refs.track(_cr, true);\n");
                }
                sb.append(ind).append("}\n");
            }

            case INVOKEDYNAMIC -> {
                InvokeDynamicInsnNode indy = (InvokeDynamicInsnNode) insn;
                if (!IndyLowerer.isStringConcat(indy)) {
                    throw new IllegalStateException("Non-StringConcat invokedynamic reached CppMethodEmitter");
                }
                Type callMt = Type.getMethodType(indy.desc);
                Type[] callArgs = callMt.getArgumentTypes();
                int argc = callArgs.length;
                int baseSlot = f.getStackSize() - argc;
                String recipe;
                int[] constIds;
                if ("makeConcatWithConstants".equals(indy.bsm.getName()) && indy.bsmArgs != null && indy.bsmArgs.length >= 1) {
                    recipe = String.valueOf(indy.bsmArgs[0]);
                    constIds = new int[indy.bsmArgs.length - 1];
                    for (int c = 1; c < indy.bsmArgs.length; c++) {
                        constIds[c - 1] = pool.internWStr(String.valueOf(indy.bsmArgs[c]));
                    }
                } else {
                    recipe = "\u0001".repeat(argc);
                    constIds = new int[0];
                }
                int recipeWid = pool.internWStr(recipe);

                sb.append(ind).append("{\n");
                String ind2 = ind + "    ";
                sb.append(ind2).append("hy::ConcatArg _cargs[").append(Math.max(1, argc)).append("];\n");
                for (int k = 0; k < argc; k++) {
                    int argSlot = baseSlot + k;
                    int ak = VmCompiler.typeToKind(callArgs[k]);
                    sb.append(ind2).append("_cargs[").append(k).append("].kind = ").append(ak).append("; ");
                    switch (callArgs[k].getSort()) {
                        case Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT ->
                                sb.append("_cargs[").append(k).append("].i = s").append(argSlot).append("_i;\n");
                        case Type.LONG -> sb.append("_cargs[").append(k).append("].j = s").append(argSlot).append("_j;\n");
                        case Type.FLOAT -> sb.append("_cargs[").append(k).append("].f = s").append(argSlot).append("_f;\n");
                        case Type.DOUBLE -> sb.append("_cargs[").append(k).append("].d = s").append(argSlot).append("_d;\n");
                        default -> sb.append("_cargs[").append(k).append("].obj = _refs.raw(s").append(argSlot).append("_l);\n");
                    }
                }
                if (constIds.length > 0) {
                    sb.append(ind2).append("int32_t _cconsts[").append(constIds.length).append("] = {");
                    for (int c = 0; c < constIds.length; c++) {
                        if (c > 0) sb.append(", ");
                        sb.append(crypto.mbaConst32(constIds[c], strong));
                    }
                    sb.append("};\n");
                }
                sb.append(ind2).append("jstring _sres = hy::string_concat(env, ")
                  .append(crypto.mbaConst32(recipeWid, strong)).append(", ")
                  .append(constIds.length > 0 ? "_cconsts" : "nullptr").append(", ").append(constIds.length)
                  .append(", _cargs, ").append(argc).append(");\n");
                sb.append(ind2).append("if (env->ExceptionCheck()) [[unlikely]] { if (_sres) env->DeleteLocalRef(_sres); ");
                emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(" }\n");
                for (int k = 0; k < argc; k++) {
                    if (callArgs[k].getSort() == Type.OBJECT || callArgs[k].getSort() == Type.ARRAY) {
                        sb.append(ind2).append("_refs.release(s").append(baseSlot + k).append("_l); s").append(baseSlot + k).append("_l = -1;\n");
                    }
                }
                sb.append(ind2).append("s").append(baseSlot).append("_l = _refs.track((jobject)_sres, true);\n");
                sb.append(ind).append("}\n");
            }

            case NEW -> {
                int clsId = pool.internClass(((TypeInsnNode) insn).desc);
                sb.append(ind).append("{\n");
                sb.append(ind).append("    jclass _nc = hy::resolve_class(env, ").append(crypto.mbaConst32(clsId, strong)).append(");\n");
                emitExCheck(sb, f.getStackSize(), f, cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(ind).append("    jobject _no = env->AllocObject(_nc);\n");
                sb.append(ind).append("    if (env->ExceptionCheck()) [[unlikely]] { if (_no) env->DeleteLocalRef(_no); ");
                emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(" }\n");
                sb.append(ind).append("    s").append(pushIdx).append("_l = _refs.track(_no, true);\n");
                sb.append(ind).append("}\n");
            }

            case NEWARRAY -> {
                int atype = ((IntInsnNode) insn).operand;
                sb.append(ind).append("if (s").append(top).append("_i < 0) { hy::throw_neg_arr(env); ");
                emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(" } else {\n");
                String arrFn = switch (atype) {
                    case T_BOOLEAN -> "NewBooleanArray";
                    case T_CHAR -> "NewCharArray";
                    case T_FLOAT -> "NewFloatArray";
                    case T_DOUBLE -> "NewDoubleArray";
                    case T_BYTE -> "NewByteArray";
                    case T_SHORT -> "NewShortArray";
                    case T_INT -> "NewIntArray";
                    default -> "NewLongArray";
                };
                sb.append(ind).append("    jarray _arr = env->").append(arrFn).append("(s").append(top).append("_i);\n");
                sb.append(ind).append("    if (env->ExceptionCheck()) [[unlikely]] { if (_arr) env->DeleteLocalRef(_arr); ");
                emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(" }\n");
                sb.append(ind).append("    s").append(top).append("_l = _refs.track((jobject)_arr, true);\n");
                sb.append(ind).append("}\n");
            }

            case ANEWARRAY -> {
                int clsId = pool.internClass(((TypeInsnNode) insn).desc);
                sb.append(ind).append("if (s").append(top).append("_i < 0) { hy::throw_neg_arr(env); ");
                emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(" } else {\n");
                sb.append(ind).append("    jclass _ec = hy::resolve_class(env, ").append(crypto.mbaConst32(clsId, strong)).append(");\n");
                emitExCheck(sb, f.getStackSize(), f, cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(ind).append("    jobjectArray _arr = env->NewObjectArray(s").append(top).append("_i, _ec, nullptr);\n");
                sb.append(ind).append("    if (env->ExceptionCheck()) [[unlikely]] { if (_arr) env->DeleteLocalRef(_arr); ");
                emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(" }\n");
                sb.append(ind).append("    s").append(top).append("_l = _refs.track((jobject)_arr, true);\n");
                sb.append(ind).append("}\n");
            }

            case MULTIANEWARRAY -> {
                MultiANewArrayInsnNode ma = (MultiANewArrayInsnNode) insn;
                int dims = ma.dims;
                int baseSlot = f.getStackSize() - dims;
                int[] clsIds = new int[dims];
                String curDesc = ma.desc.substring(1);
                for (int d = 0; d < dims; d++) {
                    Type elemT = Type.getType(curDesc);
                    clsIds[d] = (elemT.getSort() == Type.OBJECT || elemT.getSort() == Type.ARRAY)
                            ? pool.internClass(elemT.getInternalName())
                            : 0;
                    if (d + 1 < dims) curDesc = curDesc.substring(1);
                }
                sb.append(ind).append("{\n");
                sb.append(ind).append("    int32_t _dims[").append(dims).append("] = {");
                for (int d = 0; d < dims; d++) {
                    if (d > 0) sb.append(", ");
                    sb.append("s").append(baseSlot + d).append("_i");
                }
                sb.append("};\n");
                sb.append(ind).append("    int32_t _cids[").append(dims).append("] = {");
                for (int d = 0; d < dims; d++) {
                    if (d > 0) sb.append(", ");
                    sb.append(crypto.mbaConst32(clsIds[d], strong));
                }
                sb.append("};\n");
                sb.append(ind).append("    jobject _marr = hy::new_multi_array(env, _cids, _dims, ").append(dims).append(", ").append(VmCompiler.typeToKind(Type.getType(curDesc))).append(");\n");
                sb.append(ind).append("    if (env->ExceptionCheck()) [[unlikely]] { if (_marr) env->DeleteLocalRef(_marr); ");
                emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(" }\n");
                sb.append(ind).append("    s").append(baseSlot).append("_l = _refs.track(_marr, true);\n");
                sb.append(ind).append("}\n");
            }

            case ARRAYLENGTH -> {
                sb.append(ind).append("{\n");
                sb.append(ind).append("    jarray _al = (jarray)_refs.raw(s").append(top).append("_l);\n");
                sb.append(ind).append("    if (!_al) { hy::throw_npe(env); ");
                emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(" }\n");
                sb.append(ind).append("    int32_t _len = (int32_t)env->GetArrayLength(_al);\n");
                sb.append(ind).append("    _refs.release(s").append(top).append("_l); s").append(top).append("_l = -1;\n");
                sb.append(ind).append("    s").append(top).append("_i = _len;\n");
                sb.append(ind).append("}\n");
            }

            case IALOAD, LALOAD, FALOAD, DALOAD, AALOAD, BALOAD, CALOAD, SALOAD -> {
                int arrSlot = top - 1;
                int idxSlot = top;
                sb.append(ind).append("{\n");
                String ind2 = ind + "    ";
                sb.append(ind2).append("jarray _arr = (jarray)_refs.raw(s").append(arrSlot).append("_l);\n");
                sb.append(ind2).append("if (!_arr) { hy::throw_npe(env); ");
                emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(" }\n");
                sb.append(ind2).append("int32_t _idx = s").append(idxSlot).append("_i;\n");
                if (op == AALOAD) {
                    sb.append(ind2).append("jobject _elem = env->GetObjectArrayElement((jobjectArray)_arr, _idx);\n");
                    sb.append(ind2).append("if (env->ExceptionCheck()) [[unlikely]] { if (_elem) env->DeleteLocalRef(_elem); ");
                    emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                    sb.append(" }\n");
                    sb.append(ind2).append("_refs.release(s").append(arrSlot).append("_l); s").append(arrSlot).append("_l = _refs.track(_elem, true);\n");
                } else {
                    String regFn, cType, storeExpr;
                    switch (op) {
                        case IALOAD -> { cType = "jint"; regFn = "GetIntArrayRegion((jintArray)_arr, _idx, 1, &_v)"; storeExpr = "s" + arrSlot + "_i = _v;"; }
                        case LALOAD -> { cType = "jlong"; regFn = "GetLongArrayRegion((jlongArray)_arr, _idx, 1, &_v)"; storeExpr = "s" + arrSlot + "_j = _v;"; }
                        case FALOAD -> { cType = "jfloat"; regFn = "GetFloatArrayRegion((jfloatArray)_arr, _idx, 1, &_v)"; storeExpr = "s" + arrSlot + "_f = _v;"; }
                        case DALOAD -> { cType = "jdouble"; regFn = "GetDoubleArrayRegion((jdoubleArray)_arr, _idx, 1, &_v)"; storeExpr = "s" + arrSlot + "_d = _v;"; }
                        case CALOAD -> { cType = "jchar"; regFn = "GetCharArrayRegion((jcharArray)_arr, _idx, 1, &_v)"; storeExpr = "s" + arrSlot + "_i = (int32_t)(uint16_t)_v;"; }
                        case SALOAD -> { cType = "jshort"; regFn = "GetShortArrayRegion((jshortArray)_arr, _idx, 1, &_v)"; storeExpr = "s" + arrSlot + "_i = (int32_t)(int16_t)_v;"; }
                        default -> {
                            // BALOAD handles both boolean[] and byte[]
                            FrameAnalyzer.TypedValue arrVal = f.getStack(arrSlot);
                            if (arrVal.isBooleanArray()) {
                                cType = "jboolean"; regFn = "GetBooleanArrayRegion((jbooleanArray)_arr, _idx, 1, &_v)";
                                storeExpr = "s" + arrSlot + "_i = (_v ? 1 : 0);";
                            } else if (arrVal.isByteArray()) {
                                cType = "jbyte"; regFn = "GetByteArrayRegion((jbyteArray)_arr, _idx, 1, &_v)";
                                storeExpr = "s" + arrSlot + "_i = (int32_t)(int8_t)_v;";
                            } else {
                                cType = "int32_t";
                                regFn = null;
                                storeExpr = "s" + arrSlot + "_i = _v;";
                            }
                        }
                    }
                    if (regFn != null) {
                        sb.append(ind2).append(cType).append(" _v = 0; env->").append(regFn).append(";\n");
                    } else {
                        sb.append(ind2).append("int32_t _v = hy::baload_dyn(env, _arr, _idx);\n");
                    }
                    emitExCheck(sb, f.getStackSize(), f, cfg, bb, pool, crypto, strong, stateMask, retType);
                    sb.append(ind2).append("_refs.release(s").append(arrSlot).append("_l); s").append(arrSlot).append("_l = -1;\n");
                    sb.append(ind2).append(storeExpr).append("\n");
                }
                sb.append(ind).append("}\n");
            }

            case IASTORE, LASTORE, FASTORE, DASTORE, AASTORE, BASTORE, CASTORE, SASTORE -> {
                int arrSlot = top - 2;
                int idxSlot = top - 1;
                int valSlot = top;
                sb.append(ind).append("{\n");
                String ind2 = ind + "    ";
                sb.append(ind2).append("jarray _arr = (jarray)_refs.raw(s").append(arrSlot).append("_l);\n");
                sb.append(ind2).append("if (!_arr) { hy::throw_npe(env); ");
                emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(" }\n");
                sb.append(ind2).append("int32_t _idx = s").append(idxSlot).append("_i;\n");
                if (op == AASTORE) {
                    sb.append(ind2).append("env->SetObjectArrayElement((jobjectArray)_arr, _idx, _refs.raw(s").append(valSlot).append("_l));\n");
                    emitExCheck(sb, f.getStackSize(), f, cfg, bb, pool, crypto, strong, stateMask, retType);
                    sb.append(ind2).append("_refs.release(s").append(valSlot).append("_l); s").append(valSlot).append("_l = -1;\n");
                } else {
                    switch (op) {
                        case IASTORE -> sb.append(ind2).append("jint _v = s").append(valSlot).append("_i; env->SetIntArrayRegion((jintArray)_arr, _idx, 1, &_v);\n");
                        case LASTORE -> sb.append(ind2).append("jlong _v = s").append(valSlot).append("_j; env->SetLongArrayRegion((jlongArray)_arr, _idx, 1, &_v);\n");
                        case FASTORE -> sb.append(ind2).append("jfloat _v = s").append(valSlot).append("_f; env->SetFloatArrayRegion((jfloatArray)_arr, _idx, 1, &_v);\n");
                        case DASTORE -> sb.append(ind2).append("jdouble _v = s").append(valSlot).append("_d; env->SetDoubleArrayRegion((jdoubleArray)_arr, _idx, 1, &_v);\n");
                        case CASTORE -> sb.append(ind2).append("jchar _v = (jchar)s").append(valSlot).append("_i; env->SetCharArrayRegion((jcharArray)_arr, _idx, 1, &_v);\n");
                        case SASTORE -> sb.append(ind2).append("jshort _v = (jshort)s").append(valSlot).append("_i; env->SetShortArrayRegion((jshortArray)_arr, _idx, 1, &_v);\n");
                        default -> {
                            FrameAnalyzer.TypedValue arrVal = f.getStack(arrSlot);
                            if (arrVal.isBooleanArray()) {
                                sb.append(ind2).append("jboolean _v = (jboolean)(s").append(valSlot).append("_i & 1); env->SetBooleanArrayRegion((jbooleanArray)_arr, _idx, 1, &_v);\n");
                            } else if (arrVal.isByteArray()) {
                                sb.append(ind2).append("jbyte _v = (jbyte)s").append(valSlot).append("_i; env->SetByteArrayRegion((jbyteArray)_arr, _idx, 1, &_v);\n");
                            } else {
                                sb.append(ind2).append("hy::bastore_dyn(env, _arr, _idx, s").append(valSlot).append("_i);\n");
                            }
                        }
                    }
                    emitExCheck(sb, f.getStackSize(), f, cfg, bb, pool, crypto, strong, stateMask, retType);
                }
                sb.append(ind2).append("_refs.release(s").append(arrSlot).append("_l); s").append(arrSlot).append("_l = -1;\n");
                sb.append(ind).append("}\n");
            }

            case CHECKCAST -> {
                int clsId = pool.internClass(((TypeInsnNode) insn).desc);
                sb.append(ind).append("if (_refs.raw(s").append(top).append("_l) != nullptr) {\n");
                sb.append(ind).append("    jclass _cc = hy::resolve_class(env, ").append(crypto.mbaConst32(clsId, strong)).append(");\n");
                emitExCheck(sb, f.getStackSize(), f, cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(ind).append("    if (!env->IsInstanceOf(_refs.raw(s").append(top).append("_l), _cc)) { hy::throw_cce(env); ");
                emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(" }\n");
                sb.append(ind).append("}\n");
            }

            case INSTANCEOF -> {
                int clsId = pool.internClass(((TypeInsnNode) insn).desc);
                sb.append(ind).append("{\n");
                sb.append(ind).append("    jobject _io = _refs.raw(s").append(top).append("_l);\n");
                sb.append(ind).append("    int32_t _res = 0;\n");
                sb.append(ind).append("    if (_io != nullptr) {\n");
                sb.append(ind).append("        jclass _ic = hy::resolve_class(env, ").append(crypto.mbaConst32(clsId, strong)).append(");\n");
                emitExCheck(sb, f.getStackSize(), f, cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(ind).append("        _res = env->IsInstanceOf(_io, _ic) ? 1 : 0;\n");
                sb.append(ind).append("    }\n");
                sb.append(ind).append("    _refs.release(s").append(top).append("_l); s").append(top).append("_l = -1;\n");
                sb.append(ind).append("    s").append(top).append("_i = _res;\n");
                sb.append(ind).append("}\n");
            }

            case MONITORENTER -> {
                sb.append(ind).append("{\n");
                sb.append(ind).append("    jobject _mo = _refs.raw(s").append(top).append("_l);\n");
                sb.append(ind).append("    if (!_mo) { hy::throw_npe(env); ");
                emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(" }\n");
                sb.append(ind).append("    env->MonitorEnter(_mo);\n");
                sb.append(ind).append("    _refs.release(s").append(top).append("_l); s").append(top).append("_l = -1;\n");
                emitExCheck(sb, f.getStackSize() - 1, f, cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(ind).append("}\n");
            }
            case MONITOREXIT -> {
                sb.append(ind).append("{\n");
                sb.append(ind).append("    jobject _mo = _refs.raw(s").append(top).append("_l);\n");
                sb.append(ind).append("    if (!_mo) { hy::throw_npe(env); ");
                emitPendingExJump(sb, f.getStackSize(), cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(" }\n");
                sb.append(ind).append("    env->MonitorExit(_mo);\n");
                sb.append(ind).append("    _refs.release(s").append(top).append("_l); s").append(top).append("_l = -1;\n");
                emitExCheck(sb, f.getStackSize() - 1, f, cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(ind).append("}\n");
            }

            case ATHROW -> {
                sb.append(ind).append("{\n");
                sb.append(ind).append("    jthrowable _thrown_ex = (jthrowable)_refs.raw(s").append(top).append("_l);\n");
                sb.append(ind).append("    if (!_thrown_ex) { hy::throw_npe(env); } else { env->Throw(_thrown_ex); }\n");
                sb.append(ind).append("    _refs.release(s").append(top).append("_l); s").append(top).append("_l = -1;\n");
                sb.append(ind).append("    { ");
                emitPendingExJump(sb, f.getStackSize() - 1, cfg, bb, pool, crypto, strong, stateMask, retType);
                sb.append(" }\n");
                sb.append(ind).append("}\n");
                return true;
            }

            case RETURN -> { sb.append(ind).append("return;\n"); return true; }
            case IRETURN -> {
                String cast = switch (retType.getSort()) {
                    case Type.BOOLEAN -> "(jboolean)(s" + top + "_i ? JNI_TRUE : JNI_FALSE)";
                    case Type.BYTE -> "(jbyte)s" + top + "_i";
                    case Type.CHAR -> "(jchar)s" + top + "_i";
                    case Type.SHORT -> "(jshort)s" + top + "_i";
                    default -> "(jint)s" + top + "_i";
                };
                sb.append(ind).append("return ").append(cast).append(";\n");
                return true;
            }
            case LRETURN -> { sb.append(ind).append("return (jlong)s").append(top).append("_j;\n"); return true; }
            case FRETURN -> { sb.append(ind).append("return (jfloat)s").append(top).append("_f;\n"); return true; }
            case DRETURN -> { sb.append(ind).append("return (jdouble)s").append(top).append("_d;\n"); return true; }
            case ARETURN -> {
                sb.append(ind).append("return (").append(jniRetType(retType)).append(")_refs.detach_return(s").append(top).append("_l);\n");
                return true;
            }
            default -> throw new UnsupportedOperationException("Unsupported JVM opcode in CppMethodEmitter: " + op);
        }
        return false;
    }

    private static boolean tryEmitStaticIntrinsic(StringBuilder sb, String ind, MethodInsnNode mi, Frame<FrameAnalyzer.TypedValue> f) {
        int top = f.getStackSize() - 1;
        String key = mi.owner + "." + mi.name + mi.desc;
        switch (key) {
            case "java/lang/Integer.rotateLeft(II)I" -> {
                sb.append(ind).append("{ uint32_t _v = (uint32_t)s").append(top - 1).append("_i; uint32_t _d = (uint32_t)s").append(top)
                  .append("_i & 31u; s").append(top - 1).append("_i = (int32_t)((_v << _d) | (_v >> ((32u - _d) & 31u))); }\n");
                return true;
            }
            case "java/lang/Integer.rotateRight(II)I" -> {
                sb.append(ind).append("{ uint32_t _v = (uint32_t)s").append(top - 1).append("_i; uint32_t _d = (uint32_t)s").append(top)
                  .append("_i & 31u; s").append(top - 1).append("_i = (int32_t)((_v >> _d) | (_v << ((32u - _d) & 31u))); }\n");
                return true;
            }
            case "java/lang/Integer.bitCount(I)I" -> {
                sb.append(ind).append("s").append(top).append("_i = hy::j_popcnt32((uint32_t)s").append(top).append("_i);\n");
                return true;
            }
            case "java/lang/Integer.numberOfLeadingZeros(I)I" -> {
                sb.append(ind).append("s").append(top).append("_i = hy::j_clz32((uint32_t)s").append(top).append("_i);\n");
                return true;
            }
            case "java/lang/Integer.numberOfTrailingZeros(I)I" -> {
                sb.append(ind).append("s").append(top).append("_i = hy::j_ctz32((uint32_t)s").append(top).append("_i);\n");
                return true;
            }
            case "java/lang/Integer.reverseBytes(I)I" -> {
                sb.append(ind).append("s").append(top).append("_i = (int32_t)hy::j_bswap32((uint32_t)s").append(top).append("_i);\n");
                return true;
            }
            case "java/lang/Integer.min(II)I", "java/lang/Math.min(II)I" -> {
                sb.append(ind).append("s").append(top - 1).append("_i = (s").append(top - 1).append("_i < s").append(top).append("_i) ? s").append(top - 1).append("_i : s").append(top).append("_i;\n");
                return true;
            }
            case "java/lang/Integer.max(II)I", "java/lang/Math.max(II)I" -> {
                sb.append(ind).append("s").append(top - 1).append("_i = (s").append(top - 1).append("_i > s").append(top).append("_i) ? s").append(top - 1).append("_i : s").append(top).append("_i;\n");
                return true;
            }
            case "java/lang/Math.abs(I)I" -> {
                sb.append(ind).append("s").append(top).append("_i = (s").append(top).append("_i < 0) ? (int32_t)(0u - (uint32_t)s").append(top).append("_i) : s").append(top).append("_i;\n");
                return true;
            }
            case "java/lang/Long.rotateLeft(JI)J" -> {
                sb.append(ind).append("{ uint64_t _v = (uint64_t)s").append(top - 1).append("_j; uint32_t _d = (uint32_t)s").append(top)
                  .append("_i & 63u; s").append(top - 1).append("_j = (int64_t)((_v << _d) | (_v >> ((64u - _d) & 63u))); }\n");
                return true;
            }
            case "java/lang/Long.rotateRight(JI)J" -> {
                sb.append(ind).append("{ uint64_t _v = (uint64_t)s").append(top - 1).append("_j; uint32_t _d = (uint32_t)s").append(top)
                  .append("_i & 63u; s").append(top - 1).append("_j = (int64_t)((_v >> _d) | (_v << ((64u - _d) & 63u))); }\n");
                return true;
            }
            case "java/lang/Long.bitCount(J)I" -> {
                sb.append(ind).append("s").append(top).append("_i = hy::j_popcnt64((uint64_t)s").append(top).append("_j);\n");
                return true;
            }
            case "java/lang/Long.reverseBytes(J)J" -> {
                sb.append(ind).append("s").append(top).append("_j = (int64_t)hy::j_bswap64((uint64_t)s").append(top).append("_j);\n");
                return true;
            }
            case "java/lang/Long.min(JJ)J", "java/lang/Math.min(JJ)J" -> {
                sb.append(ind).append("s").append(top - 1).append("_j = (s").append(top - 1).append("_j < s").append(top).append("_j) ? s").append(top - 1).append("_j : s").append(top).append("_j;\n");
                return true;
            }
            case "java/lang/Long.max(JJ)J", "java/lang/Math.max(JJ)J" -> {
                sb.append(ind).append("s").append(top - 1).append("_j = (s").append(top - 1).append("_j > s").append(top).append("_j) ? s").append(top - 1).append("_j : s").append(top).append("_j;\n");
                return true;
            }
            case "java/lang/Math.abs(J)J" -> {
                sb.append(ind).append("s").append(top).append("_j = (s").append(top).append("_j < 0) ? (int64_t)(0ULL - (uint64_t)s").append(top).append("_j) : s").append(top).append("_j;\n");
                return true;
            }
            case "java/lang/Float.floatToRawIntBits(F)I" -> {
                sb.append(ind).append("{ uint32_t _b = 0; memcpy(&_b, &s").append(top).append("_f, 4); s").append(top).append("_i = (int32_t)_b; }\n");
                return true;
            }
            case "java/lang/Float.intBitsToFloat(I)F" -> {
                sb.append(ind).append("s").append(top).append("_f = hy::bits_to_f32((uint32_t)s").append(top).append("_i);\n");
                return true;
            }
            case "java/lang/Double.doubleToRawLongBits(D)J" -> {
                sb.append(ind).append("{ uint64_t _b = 0; memcpy(&_b, &s").append(top).append("_d, 8); s").append(top).append("_j = (int64_t)_b; }\n");
                return true;
            }
            case "java/lang/Double.longBitsToDouble(J)D" -> {
                sb.append(ind).append("s").append(top).append("_d = hy::bits_to_f64((uint64_t)s").append(top).append("_j);\n");
                return true;
            }
            case "java/lang/Math.abs(F)F" -> {
                sb.append(ind).append("s").append(top).append("_f = fabsf(s").append(top).append("_f);\n");
                return true;
            }
            case "java/lang/Math.abs(D)D" -> {
                sb.append(ind).append("s").append(top).append("_d = fabs(s").append(top).append("_d);\n");
                return true;
            }
            case "java/lang/Math.sqrt(D)D" -> {
                sb.append(ind).append("s").append(top).append("_d = sqrt(s").append(top).append("_d);\n");
                return true;
            }
            case "java/lang/Math.floor(D)D" -> {
                sb.append(ind).append("s").append(top).append("_d = floor(s").append(top).append("_d);\n");
                return true;
            }
            case "java/lang/Math.ceil(D)D" -> {
                sb.append(ind).append("s").append(top).append("_d = ceil(s").append(top).append("_d);\n");
                return true;
            }
            default -> { return false; }
        }
    }

    private static String resolveFieldOwner(FieldInsnNode fi, MixinOutliner.MixinContext mixinCtx) {
        return MixinOutliner.resolveFieldOwner(fi.owner, fi.name, fi.desc, mixinCtx);
    }

    private static String resolveMethodOwner(MethodInsnNode mi, MixinOutliner.MixinContext mixinCtx) {
        return MixinOutliner.resolveMethodOwner(mi.owner, mi.name, mi.desc, mixinCtx);
    }

    private static void emitGetField(StringBuilder sb, String ind, int dstSlot, Type ft, boolean isStatic,
                                     String clsExpr, String fidExpr, int stackDepth,
                                     ControlFlowGraph cfg, ControlFlowGraph.BasicBlock bb,
                                     SymbolPool pool, CryptoEngine crypto, boolean strong, int stateMask, Type retType) {
        sb.append(ind).append("{\n");
        String ind2 = ind + "    ";
        sb.append(ind2).append("jclass _fc = ").append(clsExpr).append(";\n");
        emitExCheck(sb, stackDepth, null, cfg, bb, pool, crypto, strong, stateMask, retType);
        sb.append(ind2).append("jfieldID _fid = ").append(fidExpr).append(";\n");
        emitExCheck(sb, stackDepth, null, cfg, bb, pool, crypto, strong, stateMask, retType);
        String sfx = jniCallSuffix(ft);
        switch (ft.getSort()) {
            case Type.BOOLEAN -> sb.append(ind2).append("s").append(dstSlot).append("_i = env->GetStaticBooleanField(_fc, _fid) ? 1 : 0;\n");
            case Type.BYTE -> sb.append(ind2).append("s").append(dstSlot).append("_i = (int32_t)(int8_t)env->GetStaticByteField(_fc, _fid);\n");
            case Type.CHAR -> sb.append(ind2).append("s").append(dstSlot).append("_i = (int32_t)(uint16_t)env->GetStaticCharField(_fc, _fid);\n");
            case Type.SHORT -> sb.append(ind2).append("s").append(dstSlot).append("_i = (int32_t)(int16_t)env->GetStaticShortField(_fc, _fid);\n");
            case Type.INT -> sb.append(ind2).append("s").append(dstSlot).append("_i = (int32_t)env->GetStaticIntField(_fc, _fid);\n");
            case Type.LONG -> sb.append(ind2).append("s").append(dstSlot).append("_j = (int64_t)env->GetStaticLongField(_fc, _fid);\n");
            case Type.FLOAT -> sb.append(ind2).append("s").append(dstSlot).append("_f = (float)env->GetStaticFloatField(_fc, _fid);\n");
            case Type.DOUBLE -> sb.append(ind2).append("s").append(dstSlot).append("_d = (double)env->GetStaticDoubleField(_fc, _fid);\n");
            default -> {
                sb.append(ind2).append("jobject _fv = env->GetStatic").append(sfx).append("Field(_fc, _fid);\n");
                sb.append(ind2).append("s").append(dstSlot).append("_l = _refs.track(_fv, true);\n");
            }
        }
        sb.append(ind).append("}\n");
    }

    private static void emitPutField(StringBuilder sb, String ind, int valSlot, Type ft, boolean isStatic,
                                     String clsExpr, String fidExpr, int stackDepth,
                                     ControlFlowGraph cfg, ControlFlowGraph.BasicBlock bb,
                                     SymbolPool pool, CryptoEngine crypto, boolean strong, int stateMask, Type retType) {
        sb.append(ind).append("{\n");
        String ind2 = ind + "    ";
        sb.append(ind2).append("jclass _fc = ").append(clsExpr).append(";\n");
        emitExCheck(sb, stackDepth, null, cfg, bb, pool, crypto, strong, stateMask, retType);
        sb.append(ind2).append("jfieldID _fid = ").append(fidExpr).append(";\n");
        emitExCheck(sb, stackDepth, null, cfg, bb, pool, crypto, strong, stateMask, retType);
        switch (ft.getSort()) {
            case Type.BOOLEAN -> sb.append(ind2).append("env->SetStaticBooleanField(_fc, _fid, s").append(valSlot).append("_i ? JNI_TRUE : JNI_FALSE);\n");
            case Type.BYTE -> sb.append(ind2).append("env->SetStaticByteField(_fc, _fid, (jbyte)s").append(valSlot).append("_i);\n");
            case Type.CHAR -> sb.append(ind2).append("env->SetStaticCharField(_fc, _fid, (jchar)s").append(valSlot).append("_i);\n");
            case Type.SHORT -> sb.append(ind2).append("env->SetStaticShortField(_fc, _fid, (jshort)s").append(valSlot).append("_i);\n");
            case Type.INT -> sb.append(ind2).append("env->SetStaticIntField(_fc, _fid, (jint)s").append(valSlot).append("_i);\n");
            case Type.LONG -> sb.append(ind2).append("env->SetStaticLongField(_fc, _fid, (jlong)s").append(valSlot).append("_j);\n");
            case Type.FLOAT -> sb.append(ind2).append("env->SetStaticFloatField(_fc, _fid, (jfloat)s").append(valSlot).append("_f);\n");
            case Type.DOUBLE -> sb.append(ind2).append("env->SetStaticDoubleField(_fc, _fid, (jdouble)s").append(valSlot).append("_d);\n");
            default -> {
                sb.append(ind2).append("env->SetStaticObjectField(_fc, _fid, _refs.raw(s").append(valSlot).append("_l));\n");
                sb.append(ind2).append("_refs.release(s").append(valSlot).append("_l); s").append(valSlot).append("_l = -1;\n");
            }
        }
        sb.append(ind).append("}\n");
    }

    private static void emitReadInstanceField(StringBuilder sb, String ind, int dstSlot, Type ft, String objVar, String fidVar) {
        switch (ft.getSort()) {
            case Type.BOOLEAN -> sb.append(ind).append("s").append(dstSlot).append("_i = env->GetBooleanField(").append(objVar).append(", ").append(fidVar).append(") ? 1 : 0;\n");
            case Type.BYTE -> sb.append(ind).append("s").append(dstSlot).append("_i = (int32_t)(int8_t)env->GetByteField(").append(objVar).append(", ").append(fidVar).append(");\n");
            case Type.CHAR -> sb.append(ind).append("s").append(dstSlot).append("_i = (int32_t)(uint16_t)env->GetCharField(").append(objVar).append(", ").append(fidVar).append(");\n");
            case Type.SHORT -> sb.append(ind).append("s").append(dstSlot).append("_i = (int32_t)(int16_t)env->GetShortField(").append(objVar).append(", ").append(fidVar).append(");\n");
            case Type.INT -> sb.append(ind).append("s").append(dstSlot).append("_i = (int32_t)env->GetIntField(").append(objVar).append(", ").append(fidVar).append(");\n");
            case Type.LONG -> sb.append(ind).append("s").append(dstSlot).append("_j = (int64_t)env->GetLongField(").append(objVar).append(", ").append(fidVar).append(");\n");
            case Type.FLOAT -> sb.append(ind).append("s").append(dstSlot).append("_f = (float)env->GetFloatField(").append(objVar).append(", ").append(fidVar).append(");\n");
            case Type.DOUBLE -> sb.append(ind).append("s").append(dstSlot).append("_d = (double)env->GetDoubleField(").append(objVar).append(", ").append(fidVar).append(");\n");
            default -> sb.append(ind).append("int32_t _tmp_res = _refs.track(env->GetObjectField(").append(objVar).append(", ").append(fidVar).append("), true);\n");
        }
    }

    private static void emitWriteInstanceField(StringBuilder sb, String ind, int valSlot, Type ft, String objVar, String fidVar) {
        switch (ft.getSort()) {
            case Type.BOOLEAN -> sb.append(ind).append("env->SetBooleanField(").append(objVar).append(", ").append(fidVar).append(", s").append(valSlot).append("_i ? JNI_TRUE : JNI_FALSE);\n");
            case Type.BYTE -> sb.append(ind).append("env->SetByteField(").append(objVar).append(", ").append(fidVar).append(", (jbyte)s").append(valSlot).append("_i);\n");
            case Type.CHAR -> sb.append(ind).append("env->SetCharField(").append(objVar).append(", ").append(fidVar).append(", (jchar)s").append(valSlot).append("_i);\n");
            case Type.SHORT -> sb.append(ind).append("env->SetShortField(").append(objVar).append(", ").append(fidVar).append(", (jshort)s").append(valSlot).append("_i);\n");
            case Type.INT -> sb.append(ind).append("env->SetIntField(").append(objVar).append(", ").append(fidVar).append(", (jint)s").append(valSlot).append("_i);\n");
            case Type.LONG -> sb.append(ind).append("env->SetLongField(").append(objVar).append(", ").append(fidVar).append(", (jlong)s").append(valSlot).append("_j);\n");
            case Type.FLOAT -> sb.append(ind).append("env->SetFloatField(").append(objVar).append(", ").append(fidVar).append(", (jfloat)s").append(valSlot).append("_f);\n");
            case Type.DOUBLE -> sb.append(ind).append("env->SetDoubleField(").append(objVar).append(", ").append(fidVar).append(", (jdouble)s").append(valSlot).append("_d);\n");
            default -> sb.append(ind).append("env->SetObjectField(").append(objVar).append(", ").append(fidVar).append(", _refs.raw(s").append(valSlot).append("_l));\n");
        }
    }

    private static void emitExCheck(StringBuilder sb, int clearDepth, Frame<FrameAnalyzer.TypedValue> f,
                                    ControlFlowGraph cfg, ControlFlowGraph.BasicBlock bb,
                                    SymbolPool pool, CryptoEngine crypto, boolean strong, int stateMask, Type retType) {
        sb.append("                if (env->ExceptionCheck()) [[unlikely]] { ");
        emitPendingExJump(sb, clearDepth, cfg, bb, pool, crypto, strong, stateMask, retType);
        sb.append(" }\n");
    }

    private static void emitPendingExJump(StringBuilder sb, int clearDepth,
                                          ControlFlowGraph cfg, ControlFlowGraph.BasicBlock bb,
                                          SymbolPool pool, CryptoEngine crypto, boolean strong, int stateMask, Type retType) {
        if (bb.activeHandlers.isEmpty()) {
            sb.append("return").append(defaultRetExpr(retType)).append(";");
            return;
        }
        sb.append("jthrowable _ex = env->ExceptionOccurred(); env->ExceptionClear(); ");
        for (int k = 0; k < clearDepth; k++) {
            sb.append("if (s").append(k).append("_l >= 0) { _refs.release(s").append(k).append("_l); s").append(k).append("_l = -1; } ");
        }
        boolean hasCatchAll = false;
        for (int h = 0; h < bb.activeHandlers.size(); h++) {
            TryCatchBlockNode tcb = bb.activeHandlers.get(h);
            ControlFlowGraph.BasicBlock hbb = cfg.labelToBlock.get(tcb.handler);
            if (hbb == null) continue;
            int encTarget = hbb.stateId ^ stateMask;
            if (tcb.type == null) {
                sb.append("s0_l = _refs.track(_ex, true); _st = (uint32_t)")
                  .append(crypto.mbaConst32(encTarget, strong)).append("; break;");
                hasCatchAll = true;
                break;
            } else {
                int clsId = pool.internClass(tcb.type);
                sb.append("{ jclass _hc = hy::resolve_class(env, ").append(crypto.mbaConst32(clsId, strong)).append("); ")
                  .append("if (env->ExceptionCheck()) env->ExceptionClear(); ")
                  .append("if (_hc && env->IsInstanceOf(_ex, _hc)) { s0_l = _refs.track(_ex, true); _st = (uint32_t)")
                  .append(crypto.mbaConst32(encTarget, strong)).append("; break; } } ");
            }
        }
        if (!hasCatchAll) {
            sb.append("env->Throw(_ex); env->DeleteLocalRef(_ex); return").append(defaultRetExpr(retType)).append(";");
        }
    }

    private static void emitDupSlot(StringBuilder sb, String ind, int dst, int src, FrameAnalyzer.TypedValue v) {
        switch (v.kind) {
            case INT -> sb.append(ind).append("s").append(dst).append("_i = s").append(src).append("_i;\n");
            case LONG -> sb.append(ind).append("s").append(dst).append("_j = s").append(src).append("_j;\n");
            case FLOAT -> sb.append(ind).append("s").append(dst).append("_f = s").append(src).append("_f;\n");
            case DOUBLE -> sb.append(ind).append("s").append(dst).append("_d = s").append(src).append("_d;\n");
            case REFERENCE -> sb.append(ind).append("s").append(dst).append("_l = _refs.retain(s").append(src).append("_l);\n");
            default -> {}
        }
    }

    private static void emitMoveSlot(StringBuilder sb, String ind, int dst, int src, FrameAnalyzer.TypedValue v) {
        switch (v.kind) {
            case INT -> sb.append(ind).append("s").append(dst).append("_i = s").append(src).append("_i;\n");
            case LONG -> sb.append(ind).append("s").append(dst).append("_j = s").append(src).append("_j;\n");
            case FLOAT -> sb.append(ind).append("s").append(dst).append("_f = s").append(src).append("_f;\n");
            case DOUBLE -> sb.append(ind).append("s").append(dst).append("_d = s").append(src).append("_d;\n");
            case REFERENCE -> sb.append(ind).append("s").append(dst).append("_l = s").append(src).append("_l; s").append(src).append("_l = -1;\n");
            default -> {}
        }
    }

    private static void emitPackJValue(StringBuilder sb, String ind, String target, int slot, Type t) {
        switch (t.getSort()) {
            case Type.BOOLEAN -> sb.append(ind).append(target).append(".z = (s").append(slot).append("_i & 1) ? JNI_TRUE : JNI_FALSE;\n");
            case Type.BYTE -> sb.append(ind).append(target).append(".b = (jbyte)s").append(slot).append("_i;\n");
            case Type.CHAR -> sb.append(ind).append(target).append(".c = (jchar)s").append(slot).append("_i;\n");
            case Type.SHORT -> sb.append(ind).append(target).append(".s = (jshort)s").append(slot).append("_i;\n");
            case Type.INT -> sb.append(ind).append(target).append(".i = (jint)s").append(slot).append("_i;\n");
            case Type.LONG -> sb.append(ind).append(target).append(".j = (jlong)s").append(slot).append("_j;\n");
            case Type.FLOAT -> sb.append(ind).append(target).append(".f = (jfloat)s").append(slot).append("_f;\n");
            case Type.DOUBLE -> sb.append(ind).append(target).append(".d = (jdouble)s").append(slot).append("_d;\n");
            default -> sb.append(ind).append(target).append(".l = _refs.raw(s").append(slot).append("_l);\n");
        }
    }

    private static void markLocalKind(int sort, int slot, boolean[] I, boolean[] J, boolean[] F, boolean[] D, boolean[] L) {
        switch (sort) {
            case Type.BOOLEAN, Type.BYTE, Type.CHAR, Type.SHORT, Type.INT -> I[slot] = true;
            case Type.LONG -> J[slot] = true;
            case Type.FLOAT -> F[slot] = true;
            case Type.DOUBLE -> D[slot] = true;
            default -> L[slot] = true;
        }
    }

    public static String jniRetType(Type t) {
        return switch (t.getSort()) {
            case Type.VOID -> "void";
            case Type.BOOLEAN -> "jboolean";
            case Type.BYTE -> "jbyte";
            case Type.CHAR -> "jchar";
            case Type.SHORT -> "jshort";
            case Type.INT -> "jint";
            case Type.LONG -> "jlong";
            case Type.FLOAT -> "jfloat";
            case Type.DOUBLE -> "jdouble";
            case Type.ARRAY -> switch (t.getDescriptor()) {
                case "[Z" -> "jbooleanArray";
                case "[B" -> "jbyteArray";
                case "[C" -> "jcharArray";
                case "[S" -> "jshortArray";
                case "[I" -> "jintArray";
                case "[J" -> "jlongArray";
                case "[F" -> "jfloatArray";
                case "[D" -> "jdoubleArray";
                default -> "jobjectArray";
            };
            default -> "java/lang/String".equals(t.getInternalName()) ? "jstring"
                    : ("java/lang/Class".equals(t.getInternalName()) ? "jclass"
                    : ("java/lang/Throwable".equals(t.getInternalName()) ? "jthrowable" : "jobject"));
        };
    }

    public static String jniParamType(Type t) {
        return jniRetType(t);
    }

    public static String jniCallSuffix(Type t) {
        return switch (t.getSort()) {
            case Type.VOID -> "Void";
            case Type.BOOLEAN -> "Boolean";
            case Type.BYTE -> "Byte";
            case Type.CHAR -> "Char";
            case Type.SHORT -> "Short";
            case Type.INT -> "Int";
            case Type.LONG -> "Long";
            case Type.FLOAT -> "Float";
            case Type.DOUBLE -> "Double";
            default -> "Object";
        };
    }

    private static String defaultRetExpr(Type t) {
        return switch (t.getSort()) {
            case Type.VOID -> "";
            case Type.BOOLEAN -> " JNI_FALSE";
            case Type.FLOAT -> " 0.0f";
            case Type.DOUBLE -> " 0.0";
            case Type.OBJECT, Type.ARRAY -> " nullptr";
            default -> " 0";
        };
    }
}
