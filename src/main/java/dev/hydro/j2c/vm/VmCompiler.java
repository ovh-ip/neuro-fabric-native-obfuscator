package dev.hydro.j2c.vm;

import dev.hydro.j2c.analysis.FrameAnalyzer;
import dev.hydro.j2c.crypto.CryptoEngine;
import dev.hydro.j2c.crypto.SymbolPool;
import dev.hydro.j2c.fabric.MixinOutliner;
import dev.hydro.j2c.preprocess.IndyLowerer;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.Frame;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Compiles a JVM MethodNode into encrypted custom VM bytecode executed inside the DLL.
 */
public final class VmCompiler implements Opcodes {

    public static final class CompiledVmMethod {
        public final int vmMethodId;
        public final byte[] rawCode;
        public final long methodSalt;
        public final int opMask;
        public final int pcMul;
        public final List<VmTryCatch> tryCatches = new ArrayList<>();
        public final List<VmCallSite> callSites = new ArrayList<>();
        public final List<VmFieldSite> fieldSites = new ArrayList<>();
        public final List<VmConcatSite> concatSites = new ArrayList<>();
        public final int maxStack;
        public final int maxLocals;
        public final String ownerInternal;
        public final String methodName;
        public final String methodDesc;
        public final boolean isStatic;
        public final String cNativeFnName;

        public CompiledVmMethod(int vmMethodId, byte[] rawCode, long methodSalt, int opMask, int pcMul,
                                int maxStack, int maxLocals, String ownerInternal, String methodName,
                                String methodDesc, boolean isStatic, String cNativeFnName) {
            this.vmMethodId = vmMethodId;
            this.rawCode = rawCode;
            this.methodSalt = methodSalt;
            this.opMask = opMask & 0xFF;
            this.pcMul = pcMul & 0xFF;
            this.maxStack = maxStack;
            this.maxLocals = maxLocals;
            this.ownerInternal = ownerInternal;
            this.methodName = methodName;
            this.methodDesc = methodDesc;
            this.isStatic = isStatic;
            this.cNativeFnName = cNativeFnName;
        }
    }

    public record VmTryCatch(int startPc, int endPc, int handlerPc, int catchClsId) {}

    public record VmCallSite(int memberId, int retKind, int[] argKinds, int flags) {}

    public record VmFieldSite(int memberId, int fieldKind, int flags) {}

    public record VmConcatSite(int recipeSymId, int[] constWStrIds, int[] argKinds) {}

    public static int typeToKind(Type t) {
        return switch (t.getSort()) {
            case Type.VOID -> 0;
            case Type.BOOLEAN -> 1;
            case Type.BYTE -> 2;
            case Type.CHAR -> 3;
            case Type.SHORT -> 4;
            case Type.INT -> 5;
            case Type.LONG -> 6;
            case Type.FLOAT -> 7;
            case Type.DOUBLE -> 8;
            default -> 9; // OBJECT / ARRAY
        };
    }

    private static final class Patch {
        final int offset; // offset of 4-byte int32 pc target
        final LabelNode label;
        Patch(int offset, LabelNode label) { this.offset = offset; this.label = label; }
    }

    public static CompiledVmMethod compile(
            int vmMethodId,
            String ownerInternal,
            MethodNode mn,
            String cNativeFnName,
            Frame<FrameAnalyzer.TypedValue>[] frames,
            VmIsa isa,
            SymbolPool pool) {
        return compile(vmMethodId, ownerInternal, mn, cNativeFnName, frames, null, isa, pool, new Random(isa.keySeed ^ vmMethodId));
    }

    public static CompiledVmMethod compile(
            int vmMethodId,
            String ownerInternal,
            MethodNode mn,
            String cNativeFnName,
            Frame<FrameAnalyzer.TypedValue>[] frames,
            MixinOutliner.MixinContext mixinCtx,
            VmIsa isa,
            SymbolPool pool,
            Random rng) {

        long methodSalt = rng.nextLong() ^ ((long) vmMethodId * 0x9E3779B97F4A7C15L);
        int opMask = rng.nextInt() & 0xFF;
        int pcMul = (rng.nextInt() | 1) & 0xFF;

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Map<LabelNode, Integer> labelOffsets = new IdentityHashMap<>();
        List<Patch> patches = new ArrayList<>();
        List<int[]> tryCatchRanges = new ArrayList<>(); // [startPc, endPc, handlerPc, clsId]

        List<VmCallSite> callSites = new ArrayList<>();
        List<VmFieldSite> fieldSites = new ArrayList<>();
        List<VmConcatSite> concatSites = new ArrayList<>();

        InsnList insns = mn.instructions;
        int n = insns.size();
        int[] insnStartPc = new int[n];
        Arrays.fill(insnStartPc, -1);

        // Pre-record label positions cleanly
        for (int i = 0; i < n; i++) {
            AbstractInsnNode insn = insns.get(i);
            insnStartPc[i] = out.size();
            if (insn instanceof LabelNode l) {
                labelOffsets.put(l, out.size());
                continue;
            }
            if (frames[i] == null || insn.getOpcode() < 0) continue;

            int op = insn.getOpcode();
            switch (op) {
                case NOP -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.NOP);
                case ACONST_NULL -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.CONST_NULL);
                case ICONST_M1, ICONST_0, ICONST_1, ICONST_2, ICONST_3, ICONST_4, ICONST_5 -> {
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.CONST_I32);
                    writeI32(out, op - ICONST_0);
                }
                case BIPUSH, SIPUSH -> {
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.CONST_I32);
                    writeI32(out, ((IntInsnNode) insn).operand);
                }
                case LCONST_0, LCONST_1 -> {
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.CONST_I64);
                    writeI64(out, op - LCONST_0);
                }
                case FCONST_0, FCONST_1, FCONST_2 -> {
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.CONST_F32);
                    writeI32(out, Float.floatToRawIntBits((float) (op - FCONST_0)));
                }
                case DCONST_0, DCONST_1 -> {
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.CONST_F64);
                    writeI64(out, Double.doubleToRawLongBits((double) (op - DCONST_0)));
                }
                case LDC -> {
                    Object cst = ((LdcInsnNode) insn).cst;
                    if (cst instanceof Integer v) {
                        writeOp(out, opMask, pcMul, isa, VmIsa.Op.CONST_I32);
                        writeI32(out, v);
                    } else if (cst instanceof Long v) {
                        writeOp(out, opMask, pcMul, isa, VmIsa.Op.CONST_I64);
                        writeI64(out, v);
                    } else if (cst instanceof Float v) {
                        writeOp(out, opMask, pcMul, isa, VmIsa.Op.CONST_F32);
                        writeI32(out, Float.floatToRawIntBits(v));
                    } else if (cst instanceof Double v) {
                        writeOp(out, opMask, pcMul, isa, VmIsa.Op.CONST_F64);
                        writeI64(out, Double.doubleToRawLongBits(v));
                    } else if (cst instanceof String s) {
                        writeOp(out, opMask, pcMul, isa, VmIsa.Op.CONST_STR);
                        writeI32(out, pool.internWStr(s));
                    } else if (cst instanceof Type t) {
                        if (t.getSort() == Type.OBJECT || t.getSort() == Type.ARRAY) {
                            writeOp(out, opMask, pcMul, isa, VmIsa.Op.CONST_CLS);
                            writeI32(out, pool.internClass(t.getInternalName()));
                        } else {
                            writeOp(out, opMask, pcMul, isa, VmIsa.Op.CONST_PRIM_CLS);
                            writeI32(out, typeToKind(t));
                        }
                    } else {
                        throw new UnsupportedOperationException("Unsupported LDC in VM: " + cst.getClass());
                    }
                }
                case ILOAD, LLOAD, FLOAD, DLOAD -> {
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.LOAD_P);
                    writeU16(out, ((VarInsnNode) insn).var);
                    out.write((op == LLOAD || op == DLOAD) ? 2 : 1);
                }
                case ALOAD -> {
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.LOAD_R);
                    writeU16(out, ((VarInsnNode) insn).var);
                }
                case ISTORE, LSTORE, FSTORE, DSTORE -> {
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.STORE_P);
                    writeU16(out, ((VarInsnNode) insn).var);
                    out.write((op == LSTORE || op == DSTORE) ? 2 : 1);
                }
                case ASTORE -> {
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.STORE_R);
                    writeU16(out, ((VarInsnNode) insn).var);
                }
                case IINC -> {
                    IincInsnNode inc = (IincInsnNode) insn;
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.IINC);
                    writeU16(out, inc.var);
                    writeI32(out, inc.incr);
                }
                case POP -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.POP1);
                case POP2 -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.POP2);
                case DUP -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.DUP1);
                case DUP_X1 -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.DUP_X1);
                case DUP_X2 -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.DUP_X2);
                case DUP2 -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.DUP2);
                case DUP2_X1 -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.DUP2_X1);
                case DUP2_X2 -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.DUP2_X2);
                case SWAP -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.SWAP);

                case IADD -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.IADD);
                case ISUB -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.ISUB);
                case IMUL -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.IMUL);
                case IDIV -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.IDIV);
                case IREM -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.IREM);
                case INEG -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.INEG);
                case ISHL -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.ISHL);
                case ISHR -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.ISHR);
                case IUSHR -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.IUSHR);
                case IAND -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.IAND);
                case IOR -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.IOR);
                case IXOR -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.IXOR);

                case LADD -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.LADD);
                case LSUB -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.LSUB);
                case LMUL -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.LMUL);
                case LDIV -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.LDIV);
                case LREM -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.LREM);
                case LNEG -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.LNEG);
                case LSHL -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.LSHL);
                case LSHR -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.LSHR);
                case LUSHR -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.LUSHR);
                case LAND -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.LAND);
                case LOR -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.LOR);
                case LXOR -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.LXOR);

                case FADD -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.FADD);
                case FSUB -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.FSUB);
                case FMUL -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.FMUL);
                case FDIV -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.FDIV);
                case FREM -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.FREM);
                case FNEG -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.FNEG);

                case DADD -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.DADD);
                case DSUB -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.DSUB);
                case DMUL -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.DMUL);
                case DDIV -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.DDIV);
                case DREM -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.DREM);
                case DNEG -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.DNEG);

                case I2L -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.I2L);
                case I2F -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.I2F);
                case I2D -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.I2D);
                case L2I -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.L2I);
                case L2F -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.L2F);
                case L2D -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.L2D);
                case F2I -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.F2I);
                case F2L -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.F2L);
                case F2D -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.F2D);
                case D2I -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.D2I);
                case D2L -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.D2L);
                case D2F -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.D2F);
                case I2B -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.I2B);
                case I2C -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.I2C);
                case I2S -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.I2S);

                case LCMP -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.LCMP);
                case FCMPL -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.FCMPL);
                case FCMPG -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.FCMPG);
                case DCMPL -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.DCMPL);
                case DCMPG -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.DCMPG);

                case GOTO -> {
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.JMP);
                    patches.add(new Patch(out.size(), ((JumpInsnNode) insn).label));
                    writeI32(out, 0);
                }
                case IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE,
                     IF_ICMPEQ, IF_ICMPNE, IF_ICMPLT, IF_ICMPGE, IF_ICMPGT, IF_ICMPLE,
                     IF_ACMPEQ, IF_ACMPNE, IFNULL, IFNONNULL -> {
                    VmIsa.Op vop = switch (op) {
                        case IFEQ -> VmIsa.Op.IF_ZERO;
                        case IFNE -> VmIsa.Op.IF_NEZ;
                        case IFLT -> VmIsa.Op.IF_LTZ;
                        case IFGE -> VmIsa.Op.IF_GEZ;
                        case IFGT -> VmIsa.Op.IF_GTZ;
                        case IFLE -> VmIsa.Op.IF_LEZ;
                        case IF_ICMPEQ -> VmIsa.Op.IF_ICMPEQ;
                        case IF_ICMPNE -> VmIsa.Op.IF_ICMPNE;
                        case IF_ICMPLT -> VmIsa.Op.IF_ICMPLT;
                        case IF_ICMPGE -> VmIsa.Op.IF_ICMPGE;
                        case IF_ICMPGT -> VmIsa.Op.IF_ICMPGT;
                        case IF_ICMPLE -> VmIsa.Op.IF_ICMPLE;
                        case IF_ACMPEQ -> VmIsa.Op.IF_ACMPEQ;
                        case IF_ACMPNE -> VmIsa.Op.IF_ACMPNE;
                        case IFNULL -> VmIsa.Op.IF_NULL;
                        default -> VmIsa.Op.IF_NONNULL;
                    };
                    writeOp(out, opMask, pcMul, isa, vop);
                    patches.add(new Patch(out.size(), ((JumpInsnNode) insn).label));
                    writeI32(out, 0);
                }
                case TABLESWITCH -> {
                    TableSwitchInsnNode ts = (TableSwitchInsnNode) insn;
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.SWITCH_TABLE);
                    writeI32(out, ts.min);
                    writeI32(out, ts.max);
                    patches.add(new Patch(out.size(), ts.dflt));
                    writeI32(out, 0);
                    for (LabelNode l : ts.labels) {
                        patches.add(new Patch(out.size(), l));
                        writeI32(out, 0);
                    }
                }
                case LOOKUPSWITCH -> {
                    LookupSwitchInsnNode ls = (LookupSwitchInsnNode) insn;
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.SWITCH_LOOKUP);
                    writeI32(out, ls.keys.size());
                    patches.add(new Patch(out.size(), ls.dflt));
                    writeI32(out, 0);
                    for (int k = 0; k < ls.keys.size(); k++) {
                        writeI32(out, ls.keys.get(k));
                        patches.add(new Patch(out.size(), ls.labels.get(k)));
                        writeI32(out, 0);
                    }
                }
                case GETSTATIC, PUTSTATIC, GETFIELD, PUTFIELD -> {
                    FieldInsnNode f = (FieldInsnNode) insn;
                    boolean isStatic = (op == GETSTATIC || op == PUTSTATIC);
                    if (MixinOutliner.isDynamicFieldAccess(f.owner, f.name, f.desc, isStatic, mixinCtx)) {
                        throw new UnsupportedOperationException("Dynamic multi-target Mixin field in VM");
                    }
                    String targetOwner = MixinOutliner.resolveFieldOwner(f.owner, f.name, f.desc, mixinCtx);
                    int memberId = pool.internField(targetOwner, f.name, f.desc, isStatic);
                    int siteId = fieldSites.size();
                    fieldSites.add(new VmFieldSite(memberId, typeToKind(Type.getType(f.desc)), 0));
                    VmIsa.Op vop = switch (op) {
                        case GETSTATIC -> VmIsa.Op.GETSTATIC;
                        case PUTSTATIC -> VmIsa.Op.PUTSTATIC;
                        case GETFIELD -> VmIsa.Op.GETFIELD;
                        default -> VmIsa.Op.PUTFIELD;
                    };
                    writeOp(out, opMask, pcMul, isa, vop);
                    writeI32(out, siteId);
                }
                case INVOKESTATIC, INVOKEVIRTUAL, INVOKESPECIAL, INVOKEINTERFACE -> {
                    MethodInsnNode m = (MethodInsnNode) insn;
                    boolean isStatic = (op == INVOKESTATIC);
                    if (MixinOutliner.isDynamicMethodAccess(m.owner, m.name, m.desc, isStatic, mixinCtx)) {
                        throw new UnsupportedOperationException("Dynamic multi-target Mixin call in VM");
                    }
                    String targetOwner = MixinOutliner.resolveMethodOwner(m.owner, m.name, m.desc, mixinCtx);
                    int memberId = pool.internMethod(targetOwner, m.name, m.desc, isStatic);
                    Type mt = Type.getMethodType(m.desc);
                    Type[] args = mt.getArgumentTypes();
                    int[] argKinds = new int[args.length];
                    for (int k = 0; k < args.length; k++) argKinds[k] = typeToKind(args[k]);
                    int siteId = callSites.size();
                    callSites.add(new VmCallSite(memberId, typeToKind(mt.getReturnType()), argKinds, 0));
                    VmIsa.Op vop = switch (op) {
                        case INVOKESTATIC -> VmIsa.Op.INVOKE_STATIC;
                        case INVOKEVIRTUAL -> VmIsa.Op.INVOKE_VIRTUAL;
                        case INVOKESPECIAL -> VmIsa.Op.INVOKE_SPECIAL;
                        default -> VmIsa.Op.INVOKE_INTERFACE;
                    };
                    writeOp(out, opMask, pcMul, isa, vop);
                    writeI32(out, siteId);
                }
                case INVOKEDYNAMIC -> {
                    InvokeDynamicInsnNode indy = (InvokeDynamicInsnNode) insn;
                    if (!IndyLowerer.isStringConcat(indy)) {
                        throw new IllegalStateException("Non-StringConcat invokedynamic must be lowered before VM");
                    }
                    Type mt = Type.getMethodType(indy.desc);
                    Type[] args = mt.getArgumentTypes();
                    int[] argKinds = new int[args.length];
                    for (int k = 0; k < args.length; k++) argKinds[k] = typeToKind(args[k]);
                    String recipe;
                    int[] constIds;
                    if ("makeConcatWithConstants".equals(indy.bsm.getName()) && indy.bsmArgs != null && indy.bsmArgs.length >= 1) {
                        recipe = String.valueOf(indy.bsmArgs[0]);
                        constIds = new int[indy.bsmArgs.length - 1];
                        for (int c = 1; c < indy.bsmArgs.length; c++) {
                            constIds[c - 1] = pool.internWStr(String.valueOf(indy.bsmArgs[c]));
                        }
                    } else {
                        recipe = "\u0001".repeat(args.length);
                        constIds = new int[0];
                    }
                    int recipeSymId = pool.internWStr(recipe);
                    int siteId = concatSites.size();
                    concatSites.add(new VmConcatSite(recipeSymId, constIds, argKinds));
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.STRING_CONCAT);
                    writeI32(out, siteId);
                }
                case NEW -> {
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.NEW_ALLOC);
                    writeI32(out, pool.internClass(((TypeInsnNode) insn).desc));
                }
                case NEWARRAY -> {
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.NEWARRAY);
                    out.write(((IntInsnNode) insn).operand);
                }
                case ANEWARRAY -> {
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.ANEWARRAY);
                    writeI32(out, pool.internClass(((TypeInsnNode) insn).desc));
                }
                case MULTIANEWARRAY -> {
                    MultiANewArrayInsnNode ma = (MultiANewArrayInsnNode) insn;
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.MULTIANEWARRAY);
                    String curDesc = ma.desc.substring(1);
                    out.write(ma.dims);
                    for (int d = 0; d < ma.dims; d++) {
                        Type elemT = Type.getType(curDesc);
                        int cid = (elemT.getSort() == Type.OBJECT || elemT.getSort() == Type.ARRAY)
                                ? pool.internClass(elemT.getInternalName())
                                : 0;
                        writeI32(out, cid);
                        if (d + 1 < ma.dims) curDesc = curDesc.substring(1);
                    }
                    out.write(typeToKind(Type.getType(curDesc)));
                }
                case ARRAYLENGTH -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.ARRAYLENGTH);
                case IALOAD, LALOAD, FALOAD, DALOAD, AALOAD, BALOAD, CALOAD, SALOAD -> {
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.ARR_LOAD);
                    int kind = switch (op) {
                        case IALOAD -> 5;
                        case LALOAD -> 6;
                        case FALOAD -> 7;
                        case DALOAD -> 8;
                        case AALOAD -> 9;
                        case BALOAD -> {
                            FrameAnalyzer.TypedValue arrVal = frames[i].getStack(frames[i].getStackSize() - 2);
                            yield arrVal.isBooleanArray() ? 1 : (arrVal.isByteArray() ? 2 : 10); // 10 = check runtime
                        }
                        case CALOAD -> 3;
                        default -> 4; // SALOAD
                    };
                    out.write(kind);
                }
                case IASTORE, LASTORE, FASTORE, DASTORE, AASTORE, BASTORE, CASTORE, SASTORE -> {
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.ARR_STORE);
                    int kind = switch (op) {
                        case IASTORE -> 5;
                        case LASTORE -> 6;
                        case FASTORE -> 7;
                        case DASTORE -> 8;
                        case AASTORE -> 9;
                        case BASTORE -> {
                            FrameAnalyzer.TypedValue arrVal = frames[i].getStack(frames[i].getStackSize() - 3);
                            yield arrVal.isBooleanArray() ? 1 : (arrVal.isByteArray() ? 2 : 10);
                        }
                        case CASTORE -> 3;
                        default -> 4;
                    };
                    out.write(kind);
                }
                case CHECKCAST -> {
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.CHECKCAST);
                    writeI32(out, pool.internClass(((TypeInsnNode) insn).desc));
                }
                case INSTANCEOF -> {
                    writeOp(out, opMask, pcMul, isa, VmIsa.Op.INSTANCEOF);
                    writeI32(out, pool.internClass(((TypeInsnNode) insn).desc));
                }
                case MONITORENTER -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.MONITORENTER);
                case MONITOREXIT -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.MONITOREXIT);
                case ATHROW -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.ATHROW);
                case RETURN -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.RET_VOID);
                case IRETURN -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.RET_I32);
                case LRETURN -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.RET_I64);
                case FRETURN -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.RET_F32);
                case DRETURN -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.RET_F64);
                case ARETURN -> writeOp(out, opMask, pcMul, isa, VmIsa.Op.RET_REF);
                default -> throw new UnsupportedOperationException("Unsupported VM opcode: " + op);
            }
        }

        byte[] raw = out.toByteArray();
        // Patch branch offsets
        for (Patch p : patches) {
            Integer targetPc = labelOffsets.get(p.label);
            if (targetPc == null) {
                throw new IllegalStateException("Missing label PC in VM compiler");
            }
            patchI32(raw, p.offset, targetPc);
        }

        CompiledVmMethod result = new CompiledVmMethod(
                vmMethodId, raw, methodSalt, opMask, pcMul,
                Math.max(4, mn.maxStack + 4), Math.max(4, mn.maxLocals + 2),
                ownerInternal, mn.name, mn.desc, (mn.access & ACC_STATIC) != 0, cNativeFnName
        );
        result.callSites.addAll(callSites);
        result.fieldSites.addAll(fieldSites);
        result.concatSites.addAll(concatSites);

        if (mn.tryCatchBlocks != null) {
            for (TryCatchBlockNode tcb : mn.tryCatchBlocks) {
                Integer sPc = labelOffsets.get(tcb.start);
                Integer ePc = labelOffsets.get(tcb.end);
                Integer hPc = labelOffsets.get(tcb.handler);
                if (sPc != null && ePc != null && hPc != null) {
                    int clsId = tcb.type == null ? -1 : pool.internClass(tcb.type);
                    result.tryCatches.add(new VmTryCatch(sPc, ePc, hPc, clsId));
                }
            }
        }
        return result;
    }

    private static void writeOp(ByteArrayOutputStream out, int opMask, int pcMul, VmIsa isa, VmIsa.Op op) {
        int insnPc = out.size();
        out.write((isa.encodeOp(op) ^ opMask ^ ((insnPc * pcMul) & 0xFF)) & 0xFF);
    }

    private static void writeU16(ByteArrayOutputStream out, int v) {
        out.write(v & 0xFF);
        out.write((v >>> 8) & 0xFF);
    }

    private static void writeI32(ByteArrayOutputStream out, int v) {
        out.write(v & 0xFF);
        out.write((v >>> 8) & 0xFF);
        out.write((v >>> 16) & 0xFF);
        out.write((v >>> 24) & 0xFF);
    }

    private static void writeI64(ByteArrayOutputStream out, long v) {
        for (int i = 0; i < 8; i++) {
            out.write((int) ((v >>> (i * 8)) & 0xFF));
        }
    }

    private static void patchI32(byte[] buf, int off, int v) {
        buf[off] = (byte) (v & 0xFF);
        buf[off + 1] = (byte) ((v >>> 8) & 0xFF);
        buf[off + 2] = (byte) ((v >>> 16) & 0xFF);
        buf[off + 3] = (byte) ((v >>> 24) & 0xFF);
    }
}
