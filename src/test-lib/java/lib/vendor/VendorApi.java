package lib.vendor;

public final class VendorApi {
    public static String signToken(String user, long nonce) {
        long m = InternalCipher.mix(nonce, user);
        return "SIG-" + Long.toUnsignedString(m, 16) + "-" + user;
    }
}
