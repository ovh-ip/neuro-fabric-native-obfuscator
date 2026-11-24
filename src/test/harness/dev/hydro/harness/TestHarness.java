package dev.hydro.harness;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * Loads the protected Fabric mod JAR inside an isolated child ClassLoader (mirroring KnotClassLoader),
 * executes all native/VM self-tests, and simulates SpongePowered Mixin merging ClientMixin.onClientTick
 * onto FakeMinecraftClient to prove @Mixin protection works end-to-end.
 */
public final class TestHarness {

    public static void main(String[] args) throws Exception {
        Path protectedJar = Path.of(args[0]);
        URL jarUrl = protectedJar.toUri().toURL();

        // Isolated child classloader whose parent is platform classloader (no test-classes on parent!)
        try (MixinSimClassLoader loader = new MixinSimClassLoader(new URL[]{jarUrl}, ClassLoader.getPlatformClassLoader(), protectedJar)) {
            Class<?> entryCls = Class.forName("dev.hydro.testmod.TestModEntrypoint", true, loader);
            Method runAll = entryCls.getDeclaredMethod("runAllSelfTests");
            String result = (String) runAll.invoke(null);
            System.out.println("[TestHarness] SelfTests => " + result);

            // Now test simulated Mixin-merged FakeMinecraftClient.onClientTick(5)!
            Class<?> clientCls = Class.forName("dev.hydro.testmod.FakeMinecraftClient", true, loader);
            Object client = clientCls.getDeclaredConstructor().newInstance();
            Method tick = clientCls.getDeclaredMethod("onClientTick", int.class);
            String tickRes = (String) tick.invoke(client, 5);
            System.out.println("[TestHarness] Mixin merged tick(5) => " + tickRes);
            // playerX starts at 100, secretInternalCalc(5) = (100+5)*3 = 315, playerX becomes 105
            if (!"1.21.4-fabric:315:105".equals(tickRes)) {
                throw new AssertionError("Mixin merged execution mismatch: " + tickRes);
            }
            System.out.println("[TestHarness] ALL CHECKS PASSED!");
        }
    }

    /**
     * Simulates SpongePowered Mixin merging ClientMixin.onClientTick trampoline into FakeMinecraftClient.
     */
    private static final class MixinSimClassLoader extends URLClassLoader {
        private final Path jarPath;

        MixinSimClassLoader(URL[] urls, ClassLoader parent, Path jarPath) {
            super(urls, parent);
            this.jarPath = jarPath;
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            if ("dev.hydro.testmod.FakeMinecraftClient".equals(name)) {
                try (JarFile jf = new JarFile(jarPath.toFile())) {
                    byte[] clientBytes = readEntry(jf, "dev/hydro/testmod/FakeMinecraftClient.class");
                    byte[] mixinBytes = readEntry(jf, "dev/hydro/testmod/mixin/ClientMixin.class");

                    ClassNode clientNode = new ClassNode();
                    new ClassReader(clientBytes).accept(clientNode, 0);
                    ClassNode mixinNode = new ClassNode();
                    new ClassReader(mixinBytes).accept(mixinNode, 0);

                    for (MethodNode mn : mixinNode.methods) {
                        if ("onClientTick".equals(mn.name)) {
                            // Copy merged trampoline method body directly onto FakeMinecraftClient
                            MethodNode merged = new MethodNode(Opcodes.ACC_PUBLIC, mn.name, mn.desc, mn.signature, null);
                            mn.accept(merged);
                            clientNode.methods.add(merged);
                        }
                    }
                    ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
                    clientNode.accept(cw);
                    byte[] mergedBytes = cw.toByteArray();
                    return defineClass(name, mergedBytes, 0, mergedBytes.length);
                } catch (Exception e) {
                    throw new ClassNotFoundException(name, e);
                }
            }
            return super.findClass(name);
        }

        private static byte[] readEntry(JarFile jf, String entryName) throws Exception {
            JarEntry je = jf.getJarEntry(entryName);
            try (InputStream is = jf.getInputStream(je); ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
                is.transferTo(bos);
                return bos.toByteArray();
            }
        }
    }
}
