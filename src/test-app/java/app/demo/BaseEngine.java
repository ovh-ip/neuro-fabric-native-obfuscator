package app.demo;

public abstract class BaseEngine implements EngineContract {
    protected int engineBias;

    protected BaseEngine(int bias) {
        this.engineBias = (bias ^ 0x55) + 11;
    }

    protected int applyBias(int input) {
        return input + engineBias;
    }
}
