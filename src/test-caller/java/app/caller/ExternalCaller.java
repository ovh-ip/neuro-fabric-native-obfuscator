package app.caller;

import lib.vendor.VendorApi;

public final class ExternalCaller {
    public static void main(String[] args) {
        String sig1 = VendorApi.signToken("alice", 42L);
        String sig2 = VendorApi.signToken("alice", 42L);
        System.out.println("LIB_CALLER_OK|" + sig1);
        if (!sig1.startsWith("SIG-") || !sig1.equals(sig2) || !sig1.endsWith("-alice")) {
            throw new AssertionError("Library invocation mismatch: " + sig1);
        }
    }
}
