package dev.hydro.j2c.vm;

import java.util.*;

/**
 * Per-build randomized custom bytecode ISA executed by the native VM inside the .dll.
 * Every build permutes opcodes bijectively over 0..255 and encrypts VM bytecode streams.
 */
public final class VmIsa {

    public enum Op {
        NOP,
        CONST_I32,
        CONST_I64,
        CONST_F32,
        CONST_F64,
        CONST_NULL,
        CONST_STR,
        CONST_CLS,
        CONST_PRIM_CLS,

        LOAD_P,   // int/float/long/double slot
        STORE_P,
        LOAD_R,   // object ref slot
        STORE_R,
        IINC,

        POP1,
        POP2,
        DUP1,
        DUP_X1,
        DUP_X2,
        DUP2,
        DUP2_X1,
        DUP2_X2,
        SWAP,

        IADD, ISUB, IMUL, IDIV, IREM, INEG, ISHL, ISHR, IUSHR, IAND, IOR, IXOR,
        LADD, LSUB, LMUL, LDIV, LREM, LNEG, LSHL, LSHR, LUSHR, LAND, LOR, LXOR,
        FADD, FSUB, FMUL, FDIV, FREM, FNEG,
        DADD, DSUB, DMUL, DDIV, DREM, DNEG,

        I2L, I2F, I2D, L2I, L2F, L2D, F2I, F2L, F2D, D2I, D2L, D2F, I2B, I2C, I2S,
        LCMP, FCMPL, FCMPG, DCMPL, DCMPG,

        JMP,
        IF_ZERO, IF_NEZ, IF_LTZ, IF_GEZ, IF_GTZ, IF_LEZ,
        IF_ICMPEQ, IF_ICMPNE, IF_ICMPLT, IF_ICMPGE, IF_ICMPGT, IF_ICMPLE,
        IF_ACMPEQ, IF_ACMPNE, IF_NULL, IF_NONNULL,
        SWITCH_TABLE,
        SWITCH_LOOKUP,

        GETSTATIC, PUTSTATIC, GETFIELD, PUTFIELD,
        INVOKE_STATIC, INVOKE_VIRTUAL, INVOKE_SPECIAL, INVOKE_INTERFACE,
        STRING_CONCAT,

        NEW_ALLOC,
        NEWARRAY,
        ANEWARRAY,
        MULTIANEWARRAY,
        ARRAYLENGTH,
        ARR_LOAD,
        ARR_STORE,
        CHECKCAST,
        INSTANCEOF,
        MONITORENTER,
        MONITOREXIT,
        ATHROW,

        RET_VOID,
        RET_I32,
        RET_I64,
        RET_F32,
        RET_F64,
        RET_REF
    }

    public final Map<Op, Integer> opcodeMap = new EnumMap<>(Op.class);
    public final long keySeed;
    public final int immKey32;

    public VmIsa(Random rng) {
        this.keySeed = rng.nextLong();
        this.immKey32 = rng.nextInt();
        List<Integer> pool = new ArrayList<>(256);
        for (int i = 0; i < 256; i++) pool.add(i);
        Collections.shuffle(pool, rng);
        Op[] ops = Op.values();
        for (int i = 0; i < ops.length; i++) {
            opcodeMap.put(ops[i], pool.get(i));
        }
    }

    public int encodeOp(Op op) {
        return opcodeMap.get(op);
    }
}
