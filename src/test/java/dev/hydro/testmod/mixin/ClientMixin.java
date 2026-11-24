package dev.hydro.testmod.mixin;

import dev.hydro.testmod.FakeMinecraftClient;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.injection.Inject;

/**
 * Simulates a Fabric @Mixin class with @Shadow members and @Inject hook.
 * Notice: MixinOutliner must leave the @Inject method as a non-native trampoline
 * while hiding the entire hook logic inside a native bridge class in the .dll!
 */
@Mixin(FakeMinecraftClient.class)
public abstract class ClientMixin {
    @Shadow
    private static String VERSION;

    @Shadow
    private int playerX;

    @Shadow
    private String lastMessage;

    @Shadow
    protected abstract int secretInternalCalc(int delta);

    @Inject(method = "tick")
    public String onClientTick(int delta) {
        int val = this.secretInternalCalc(delta);
        this.playerX += delta;
        this.lastMessage = VERSION + ":" + val + ":" + this.playerX;
        return this.lastMessage;
    }
}
