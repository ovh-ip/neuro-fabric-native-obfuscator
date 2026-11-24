package dev.hydro.j2c.analysis;

import org.objectweb.asm.ConstantDynamic;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.analysis.*;

import java.util.List;

/**
 * Performs JVM dataflow verification and computes exact computational types for every local slot
 * and operand stack position prior to every instruction in a MethodNode.
 */
public final class FrameAnalyzer {

    public enum Kind {
        UNINITIALIZED,
        INT,
        FLOAT,
        LONG,
        DOUBLE,
        REFERENCE
    }

    public static final class TypedValue implements Value {
        public final Kind kind;
        public final Type type; // non-null for REFERENCE when known (e.g. [Z vs [B)

        public static final TypedValue UNINIT = new TypedValue(Kind.UNINITIALIZED, null);
        public static final TypedValue INT = new TypedValue(Kind.INT, Type.INT_TYPE);
        public static final TypedValue FLOAT = new TypedValue(Kind.FLOAT, Type.FLOAT_TYPE);
        public static final TypedValue LONG = new TypedValue(Kind.LONG, Type.LONG_TYPE);
        public static final TypedValue DOUBLE = new TypedValue(Kind.DOUBLE, Type.DOUBLE_TYPE);
        public static final TypedValue REF_OBJ = new TypedValue(Kind.REFERENCE, Type.getObjectType("java/lang/Object"));
        public static final TypedValue REF_NULL = new TypedValue(Kind.REFERENCE, Type.getObjectType("null"));

        public TypedValue(Kind kind, Type type) {
            this.kind = kind;
            this.type = type;
        }

        @Override
        public int getSize() {
            return (kind == Kind.LONG || kind == Kind.DOUBLE) ? 2 : 1;
        }

        public boolean isBooleanArray() {
            return kind == Kind.REFERENCE && type != null && "[Z".equals(type.getDescriptor());
        }

        public boolean isByteArray() {
            return kind == Kind.REFERENCE && type != null && "[B".equals(type.getDescriptor());
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof TypedValue other)) return false;
            if (kind != other.kind) return false;
            if (kind != Kind.REFERENCE) return true;
            return java.util.Objects.equals(type, other.type);
        }

        @Override
        public int hashCode() {
            return kind.hashCode() * 31 + (kind == Kind.REFERENCE && type != null ? type.hashCode() : 0);
        }
    }

    private static final class TypedInterpreter extends Interpreter<TypedValue> implements Opcodes {
        TypedInterpreter() {
            super(ASM9);
        }

        @Override
        public TypedValue newValue(Type type) {
            if (type == null) return TypedValue.UNINIT;
            return switch (type.getSort()) {
                case Type.VOID -> null;
                case Type.BOOLEAN, Type.CHAR, Type.BYTE, Type.SHORT, Type.INT -> TypedValue.INT;
                case Type.FLOAT -> TypedValue.FLOAT;
                case Type.LONG -> TypedValue.LONG;
                case Type.DOUBLE -> TypedValue.DOUBLE;
                case Type.ARRAY, Type.OBJECT -> new TypedValue(Kind.REFERENCE, type);
                default -> throw new IllegalArgumentException("Unexpected type: " + type);
            };
        }

        @Override
        public TypedValue newOperation(AbstractInsnNode insn) throws AnalyzerException {
            return switch (insn.getOpcode()) {
                case ACONST_NULL -> TypedValue.REF_NULL;
                case ICONST_M1, ICONST_0, ICONST_1, ICONST_2, ICONST_3, ICONST_4, ICONST_5, BIPUSH, SIPUSH -> TypedValue.INT;
                case LCONST_0, LCONST_1 -> TypedValue.LONG;
                case FCONST_0, FCONST_1, FCONST_2 -> TypedValue.FLOAT;
                case DCONST_0, DCONST_1 -> TypedValue.DOUBLE;
                case LDC -> {
                    Object cst = ((org.objectweb.asm.tree.LdcInsnNode) insn).cst;
                    if (cst instanceof Integer) yield TypedValue.INT;
                    if (cst instanceof Float) yield TypedValue.FLOAT;
                    if (cst instanceof Long) yield TypedValue.LONG;
                    if (cst instanceof Double) yield TypedValue.DOUBLE;
                    if (cst instanceof String) yield newValue(Type.getObjectType("java/lang/String"));
                    if (cst instanceof Type t) {
                        int sort = t.getSort();
                        if (sort == Type.OBJECT || sort == Type.ARRAY || sort == Type.METHOD) {
                            yield newValue(Type.getObjectType(sort == Type.METHOD ? "java/lang/invoke/MethodType" : "java/lang/Class"));
                        }
                        yield newValue(Type.getObjectType("java/lang/Class"));
                    }
                    if (cst instanceof Handle) yield newValue(Type.getObjectType("java/lang/invoke/MethodHandle"));
                    if (cst instanceof ConstantDynamic cd) yield newValue(Type.getType(cd.getDescriptor()));
                    yield TypedValue.REF_OBJ;
                }
                case JSR -> TypedValue.UNINIT;
                case GETSTATIC -> newValue(Type.getType(((org.objectweb.asm.tree.FieldInsnNode) insn).desc));
                case NEW -> newValue(Type.getObjectType(((org.objectweb.asm.tree.TypeInsnNode) insn).desc));
                default -> throw new AnalyzerException(insn, "Unexpected newOperation: " + insn.getOpcode());
            };
        }

        @Override
        public TypedValue copyOperation(AbstractInsnNode insn, TypedValue value) {
            return value;
        }

        @Override
        public TypedValue unaryOperation(AbstractInsnNode insn, TypedValue value) throws AnalyzerException {
            return switch (insn.getOpcode()) {
                case INEG, IINC, L2I, F2I, D2I, I2B, I2C, I2S,
                     IFEQ, IFNE, IFLT, IFGE, IFGT, IFLE,
                     TABLESWITCH, LOOKUPSWITCH, IRETURN, LRETURN, FRETURN, DRETURN, ARETURN,
                     PUTSTATIC, ATHROW, ARRAYLENGTH, MONITORENTER, MONITOREXIT,
                     IFNULL, IFNONNULL, INSTANCEOF -> switch (insn.getOpcode()) {
                    case INEG, IINC, L2I, F2I, D2I, I2B, I2C, I2S, ARRAYLENGTH, INSTANCEOF -> TypedValue.INT;
                    default -> null;
                };
                case FNEG, I2F, L2F, D2F -> TypedValue.FLOAT;
                case LNEG, I2L, F2L, D2L -> TypedValue.LONG;
                case DNEG, I2D, L2D, F2D -> TypedValue.DOUBLE;
                case GETFIELD -> newValue(Type.getType(((org.objectweb.asm.tree.FieldInsnNode) insn).desc));
                case NEWARRAY -> switch (((org.objectweb.asm.tree.IntInsnNode) insn).operand) {
                    case T_BOOLEAN -> newValue(Type.getType("[Z"));
                    case T_CHAR -> newValue(Type.getType("[C"));
                    case T_FLOAT -> newValue(Type.getType("[F"));
                    case T_DOUBLE -> newValue(Type.getType("[D"));
                    case T_BYTE -> newValue(Type.getType("[B"));
                    case T_SHORT -> newValue(Type.getType("[S"));
                    case T_INT -> newValue(Type.getType("[I"));
                    case T_LONG -> newValue(Type.getType("[J"));
                    default -> throw new AnalyzerException(insn, "Invalid array type");
                };
                case ANEWARRAY -> newValue(Type.getType("[" + Type.getObjectType(((org.objectweb.asm.tree.TypeInsnNode) insn).desc).getDescriptor()));
                case CHECKCAST -> newValue(Type.getObjectType(((org.objectweb.asm.tree.TypeInsnNode) insn).desc));
                default -> throw new AnalyzerException(insn, "Unexpected unaryOperation: " + insn.getOpcode());
            };
        }

        @Override
        public TypedValue binaryOperation(AbstractInsnNode insn, TypedValue v1, TypedValue v2) throws AnalyzerException {
            return switch (insn.getOpcode()) {
                case IALOAD, BALOAD, CALOAD, SALOAD,
                     IADD, ISUB, IMUL, IDIV, IREM, ISHL, ISHR, IUSHR, IAND, IOR, IXOR,
                     LCMP, FCMPL, FCMPG, DCMPL, DCMPG -> TypedValue.INT;
                case FALOAD, FADD, FSUB, FMUL, FDIV, FREM -> TypedValue.FLOAT;
                case LALOAD, LADD, LSUB, LMUL, LDIV, LREM, LSHL, LSHR, LUSHR, LAND, LOR, LXOR -> TypedValue.LONG;
                case DALOAD, DADD, DSUB, DMUL, DDIV, DREM -> TypedValue.DOUBLE;
                case AALOAD -> {
                    if (v1.type != null && v1.type.getSort() == Type.ARRAY && v1.type.getDimensions() >= 1) {
                        String desc = v1.type.getDescriptor();
                        yield newValue(Type.getType(desc.substring(1)));
                    }
                    yield TypedValue.REF_OBJ;
                }
                case IF_ICMPEQ, IF_ICMPNE, IF_ICMPLT, IF_ICMPGE, IF_ICMPGT, IF_ICMPLE,
                     IF_ACMPEQ, IF_ACMPNE, PUTFIELD -> null;
                default -> throw new AnalyzerException(insn, "Unexpected binaryOperation: " + insn.getOpcode());
            };
        }

        @Override
        public TypedValue ternaryOperation(AbstractInsnNode insn, TypedValue v1, TypedValue v2, TypedValue v3) {
            return null;
        }

        @Override
        public TypedValue naryOperation(AbstractInsnNode insn, List<? extends TypedValue> values) {
            int op = insn.getOpcode();
            if (op == MULTIANEWARRAY) {
                return newValue(Type.getType(((org.objectweb.asm.tree.MultiANewArrayInsnNode) insn).desc));
            }
            if (op == INVOKEDYNAMIC) {
                return newValue(Type.getReturnType(((org.objectweb.asm.tree.InvokeDynamicInsnNode) insn).desc));
            }
            return newValue(Type.getReturnType(((org.objectweb.asm.tree.MethodInsnNode) insn).desc));
        }

        @Override
        public void returnOperation(AbstractInsnNode insn, TypedValue value, TypedValue expected) {
        }

        @Override
        public TypedValue merge(TypedValue v1, TypedValue v2) {
            if (v1.equals(v2)) return v1;
            if (v1.kind != v2.kind) return TypedValue.UNINIT;
            if (v1.kind == Kind.REFERENCE) {
                if (TypedValue.REF_NULL.equals(v1)) return v2;
                if (TypedValue.REF_NULL.equals(v2)) return v1;
                if (v1.type != null && v1.type.equals(v2.type)) return v1;
                return TypedValue.REF_OBJ;
            }
            return v1;
        }
    }

    public static Frame<TypedValue>[] analyze(String ownerInternalName, MethodNode mn) throws AnalyzerException {
        Analyzer<TypedValue> analyzer = new Analyzer<>(new TypedInterpreter());
        return analyzer.analyze(ownerInternalName, mn);
    }
}
