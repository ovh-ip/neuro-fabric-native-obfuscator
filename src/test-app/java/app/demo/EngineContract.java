package app.demo;

public interface EngineContract {
    int runKernel(int seed, int multiplier);

    default int contractBoost(int value) {
        return value * 3 + 7;
    }

    static String contractTag() {
        return "CONTRACT-V1";
    }
}
