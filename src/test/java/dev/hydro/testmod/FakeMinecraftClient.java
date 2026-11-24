package dev.hydro.testmod;

public class FakeMinecraftClient {
    private static final String VERSION = "1.21.4-fabric";
    private int playerX = 100;
    private String lastMessage = "";

    public int getPlayerX() {
        return playerX;
    }

    public String getLastMessage() {
        return lastMessage;
    }

    private int secretInternalCalc(int delta) {
        return (playerX + delta) * 3;
    }
}
