package app.demo;

public final class CliMain extends BaseEngine {

    public CliMain(int bias) {
        super(bias);
    }

    @Override
    public int runKernel(int seed, int multiplier) {
        int val = applyBias(seed) * multiplier;
        return contractBoost(val);
    }

    public static void main(String[] args) {
        CliMain engine = new CliMain(10);
        int seed = args.length > 0 ? Integer.parseInt(args[0]) : 4;
        String joinedArgs = String.join(",", args);
        int kernel = engine.runKernel(seed, 5);
        String report = SecretCore.computeReport(seed, SecretCore.Mode.DEEP, EngineContract.contractTag());
        String errCase = SecretCore.computeReport(-3, SecretCore.Mode.FAST, "NEG");
        System.out.println("APP_OK|args=" + joinedArgs + "|kernel=" + kernel + "|" + report + "|err=" + errCase);
        if (kernel <= 0 || !report.contains("HYDRO_APP_BANNER_2026") || !errCase.equals("ERR:NEGATIVE_SEED:-3")) {
            throw new AssertionError("Self-check failed: kernel=" + kernel + " report=" + report + " err=" + errCase);
        }
        if (args.length >= 2 && "watch".equals(args[1])) {
            for (int i = 0; i < 24; i++) {
                try { Thread.sleep(500); } catch (InterruptedException ignored) {}
                int k2 = engine.runKernel(seed, 5);
                if (k2 != kernel) {
                    System.out.println("SESSION_INVALIDATED:" + k2);
                    System.exit(42);
                }
            }
        }
    }
}
