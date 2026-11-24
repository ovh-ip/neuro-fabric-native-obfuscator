package dev.hydro.j2c.preprocess;

import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodNode;

/**
 * Strips debug metadata (SourceFile, SourceDebugExtension, LineNumberNode, LocalVariableNode,
 * MethodParameters) from protected classes to eliminate reverse-engineering clues.
 */
public final class JavaPreHardener {

    public static void stripDebugInfo(ClassNode cn) {
        cn.sourceFile = null;
        cn.sourceDebug = null;
        if (cn.methods == null) return;
        for (MethodNode mn : cn.methods) {
            mn.localVariables = null;
            mn.parameters = null;
            if (mn.instructions != null) {
                for (AbstractInsnNode cur = mn.instructions.getFirst(); cur != null; ) {
                    AbstractInsnNode next = cur.getNext();
                    if (cur instanceof LineNumberNode) {
                        mn.instructions.remove(cur);
                    }
                    cur = next;
                }
            }
        }
    }
}
