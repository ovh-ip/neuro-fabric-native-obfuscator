package app.annot;

// Deliberately NOT @Native: tests that Main stays a pure stubless Java entrypoint
// while HLoader.boot() unpacks @Native/@NativeVM .fucked classes automatically on startup.
public class AnnotOnlyMain {
    public static void main(String[] args) {
        String label = args.length > 0 ? args[0] : "cli";
        String res = AnnotatedVault.cffSecret(label);
        int plain = AnnotatedVault.plainHelper(23);
        System.out.println("APP_ANN_OK|" + res + "|plain=" + plain);
        if (!res.startsWith("VAULT:" + label + ":") || plain != 123) {
            throw new AssertionError("AnnotOnlyMain mismatch: " + res + ", plain=" + plain);
        }
    }
}
