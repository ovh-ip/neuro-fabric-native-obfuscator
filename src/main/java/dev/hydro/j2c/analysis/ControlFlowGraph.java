package dev.hydro.j2c.analysis;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.*;
import org.objectweb.asm.tree.analysis.Frame;

import java.util.*;

/**
 * Partitions a method's instruction list into BasicBlocks aligned on jump targets,
 * terminators, and TryCatchBlock boundaries so every instruction in a BasicBlock
 * shares an identical active exception handler chain.
 */
public final class ControlFlowGraph {

    public static final class BasicBlock {
        public final int id;
        public final int startInsn;
        public final int endInsn; // inclusive
        public int stateId;
        public boolean isExceptionHandler;
        public final List<TryCatchBlockNode> activeHandlers = new ArrayList<>();

        public BasicBlock(int id, int startInsn, int endInsn) {
            this.id = id;
            this.startInsn = startInsn;
            this.endInsn = endInsn;
        }
    }

    public final List<BasicBlock> blocks;
    public final Map<LabelNode, BasicBlock> labelToBlock;

    private ControlFlowGraph(List<BasicBlock> blocks, Map<LabelNode, BasicBlock> labelToBlock) {
        this.blocks = blocks;
        this.labelToBlock = labelToBlock;
    }

    public static ControlFlowGraph build(MethodNode mn, Frame<FrameAnalyzer.TypedValue>[] frames, Random rng) {
        InsnList insns = mn.instructions;
        int n = insns.size();
        boolean[] isLeader = new boolean[n];
        if (n > 0) isLeader[0] = true;

        Set<LabelNode> handlerLabels = new HashSet<>();
        if (mn.tryCatchBlocks != null) {
            for (TryCatchBlockNode tcb : mn.tryCatchBlocks) {
                markLeader(insns, isLeader, tcb.start);
                markLeader(insns, isLeader, tcb.end);
                markLeader(insns, isLeader, tcb.handler);
                handlerLabels.add(tcb.handler);
            }
        }

        for (int i = 0; i < n; i++) {
            if (frames[i] == null) continue;
            AbstractInsnNode insn = insns.get(i);
            int op = insn.getOpcode();
            if (insn instanceof JumpInsnNode j) {
                markLeader(insns, isLeader, j.label);
                if (i + 1 < n) isLeader[i + 1] = true;
            } else if (insn instanceof TableSwitchInsnNode ts) {
                markLeader(insns, isLeader, ts.dflt);
                for (LabelNode l : ts.labels) markLeader(insns, isLeader, l);
                if (i + 1 < n) isLeader[i + 1] = true;
            } else if (insn instanceof LookupSwitchInsnNode ls) {
                markLeader(insns, isLeader, ls.dflt);
                for (LabelNode l : ls.labels) markLeader(insns, isLeader, l);
                if (i + 1 < n) isLeader[i + 1] = true;
            } else if ((op >= Opcodes.IRETURN && op <= Opcodes.RETURN) || op == Opcodes.ATHROW) {
                if (i + 1 < n) isLeader[i + 1] = true;
            }
        }

        // Also treat every LabelNode that has frames as a leader if reachable or referenced
        List<BasicBlock> blocks = new ArrayList<>();
        Map<LabelNode, BasicBlock> labelToBlock = new IdentityHashMap<>();
        Set<Integer> usedStateIds = new HashSet<>();

        int idx = 0;
        while (idx < n) {
            if (frames[idx] == null) {
                idx++;
                continue;
            }
            int start = idx;
            idx++;
            while (idx < n && !isLeader[idx] && frames[idx] != null) {
                idx++;
            }
            int end = idx - 1;
            BasicBlock bb = new BasicBlock(blocks.size(), start, end);
            int sid;
            do {
                sid = rng.nextInt() | 1; // keep odd/non-zero
            } while (!usedStateIds.add(sid) || sid == 0);
            bb.stateId = sid;

            // Compute active try-catch handlers covering `start`
            if (mn.tryCatchBlocks != null) {
                for (TryCatchBlockNode tcb : mn.tryCatchBlocks) {
                    int s = insns.indexOf(tcb.start);
                    int e = insns.indexOf(tcb.end);
                    if (start >= s && start < e) {
                        bb.activeHandlers.add(tcb);
                    }
                }
            }

            // Map any labels inside this block (if start itself is a label or consecutive labels at start)
            for (int k = start; k <= end; k++) {
                AbstractInsnNode node = insns.get(k);
                if (node instanceof LabelNode l) {
                    labelToBlock.put(l, bb);
                    if (handlerLabels.contains(l)) {
                        bb.isExceptionHandler = true;
                    }
                } else if (node.getOpcode() >= 0) {
                    break; // labels only precede real insns at block start since jump targets are leaders
                }
            }
            blocks.add(bb);
        }

        // Map trailing/dead labels just in case
        for (int i = 0; i < n; i++) {
            AbstractInsnNode node = insns.get(i);
            if (node instanceof LabelNode l && !labelToBlock.containsKey(l)) {
                // Find the next live block at or after i
                for (BasicBlock bb : blocks) {
                    if (bb.startInsn >= i) {
                        labelToBlock.put(l, bb);
                        if (handlerLabels.contains(l)) bb.isExceptionHandler = true;
                        break;
                    }
                }
            }
        }

        return new ControlFlowGraph(blocks, labelToBlock);
    }

    private static void markLeader(InsnList insns, boolean[] isLeader, LabelNode label) {
        if (label == null) return;
        int idx = insns.indexOf(label);
        if (idx >= 0 && idx < isLeader.length) {
            isLeader[idx] = true;
        }
    }
}
