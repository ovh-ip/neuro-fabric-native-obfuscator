package app.demo;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.function.IntUnaryOperator;

public class SecretCore {

    public record Point(int x, int y) {
        public int normSq() {
            return x * x + y * y;
        }
    }

    public enum Mode {
        FAST(3),
        DEEP(7);

        private final int weight;

        Mode(int weight) {
            this.weight = weight;
        }

        public int weight() {
            return weight;
        }
    }

    public static final class Vault {
        private final int salt;

        public Vault(int salt) {
            this.salt = salt ^ 0x1357;
        }

        public int seal(int v) {
            IntUnaryOperator op = x -> (x * 17 + salt) ^ 0xA5A5;
            return op.applyAsInt(v);
        }
    }

    public static String computeReport(int seed, Mode mode, String tag) {
        Point pt = new Point(seed, seed + 2);
        Vault vault = new Vault(seed * 5);
        List<Integer> items = List.of(pt.normSq(), mode.weight(), vault.seal(seed));
        int acc = items.stream().mapToInt(Integer::intValue).sum();
        String banner = loadBanner();
        try {
            if (seed < 0) {
                throw new IllegalArgumentException("NEGATIVE_SEED:" + seed);
            }
        } catch (IllegalArgumentException ex) {
            return "ERR:" + ex.getMessage();
        }
        return "core=" + acc + "|pt=" + pt + "|tag=" + tag + "|res=" + banner;
    }

    private static String loadBanner() {
        try (InputStream is = SecretCore.class.getResourceAsStream("/app-banner.txt")) {
            if (is == null) return "MISSING";
            try (BufferedReader br = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line = br.readLine();
                return line != null ? line.trim() : "EMPTY";
            }
        } catch (Exception e) {
            return "EX:" + e.getClass().getSimpleName();
        }
    }
}
