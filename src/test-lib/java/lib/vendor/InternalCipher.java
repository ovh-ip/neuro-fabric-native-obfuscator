package lib.vendor;

class InternalCipher {
    static long mix(long x, String key) {
        long h = x ^ 0x9E3779B97F4A7C15L;
        for (int i = 0; i < key.length(); i++) {
            h = Long.rotateLeft(h ^ key.charAt(i), 7) * 0xBF58476D1CE4E5B9L;
        }
        return h;
    }
}
