package dev.hydro.j2c.crypto;

import java.util.*;

/**
 * Deduplicates and assigns opaque IDs to every UTF-8 symbol, UTF-16 Java string literal,
 * cached jclass, cached jmethodID, and cached jfieldID referenced by native/VM methods.
 */
public final class SymbolPool {

    public static final class SymEntry {
        public final int id;
        public final String value;
        public final byte[] encrypted;

        SymEntry(int id, String value, byte[] encrypted) {
            this.id = id;
            this.value = value;
            this.encrypted = encrypted;
        }
    }

    public static final class WStrEntry {
        public final int id;
        public final String value;
        public final short[] encrypted;

        WStrEntry(int id, String value, short[] encrypted) {
            this.id = id;
            this.value = value;
            this.encrypted = encrypted;
        }
    }

    public record ClassRef(int id, int symId) {}

    public record MemberRef(int id, int classId, int nameSymId, int descSymId, boolean isStatic) {}

    private final CryptoEngine crypto;

    private final Map<String, Integer> symMap = new LinkedHashMap<>();
    private final List<SymEntry> symEntries = new ArrayList<>();

    private final Map<String, Integer> wstrMap = new LinkedHashMap<>();
    private final List<WStrEntry> wstrEntries = new ArrayList<>();

    private final Map<String, Integer> classMap = new LinkedHashMap<>();
    private final List<ClassRef> classRefs = new ArrayList<>();

    private final Map<String, Integer> methodMap = new LinkedHashMap<>();
    private final List<MemberRef> methodRefs = new ArrayList<>();

    private final Map<String, Integer> fieldMap = new LinkedHashMap<>();
    private final List<MemberRef> fieldRefs = new ArrayList<>();

    public SymbolPool(CryptoEngine crypto) {
        this.crypto = crypto;
    }

    public int internSym(String s) {
        Integer existing = symMap.get(s);
        if (existing != null) return existing;
        int id = symEntries.size();
        symMap.put(s, id);
        symEntries.add(new SymEntry(id, s, crypto.encryptUtf8(s, id)));
        return id;
    }

    public int internWStr(String s) {
        Integer existing = wstrMap.get(s);
        if (existing != null) return existing;
        int id = wstrEntries.size();
        wstrMap.put(s, id);
        wstrEntries.add(new WStrEntry(id, s, crypto.encryptUtf16(s, id)));
        return id;
    }

    public int internClass(String internalName) {
        Integer existing = classMap.get(internalName);
        if (existing != null) return existing;
        int id = classRefs.size();
        int symId = internSym(internalName);
        classMap.put(internalName, id);
        classRefs.add(new ClassRef(id, symId));
        return id;
    }

    public int internMethod(String ownerInternalName, String name, String desc, boolean isStatic) {
        String key = (isStatic ? "S:" : "I:") + ownerInternalName + "." + name + desc;
        Integer existing = methodMap.get(key);
        if (existing != null) return existing;
        int id = methodRefs.size();
        int clsId = internClass(ownerInternalName);
        int nameId = internSym(name);
        int descId = internSym(desc);
        methodMap.put(key, id);
        methodRefs.add(new MemberRef(id, clsId, nameId, descId, isStatic));
        return id;
    }

    public int internField(String ownerInternalName, String name, String desc, boolean isStatic) {
        String key = (isStatic ? "S:" : "I:") + ownerInternalName + "." + name + ":" + desc;
        Integer existing = fieldMap.get(key);
        if (existing != null) return existing;
        int id = fieldRefs.size();
        int clsId = internClass(ownerInternalName);
        int nameId = internSym(name);
        int descId = internSym(desc);
        fieldMap.put(key, id);
        fieldRefs.add(new MemberRef(id, clsId, nameId, descId, isStatic));
        return id;
    }

    public List<SymEntry> getSymEntries() { return symEntries; }
    public List<WStrEntry> getWStrEntries() { return wstrEntries; }
    public List<ClassRef> getClassRefs() { return classRefs; }
    public List<MemberRef> getMethodRefs() { return methodRefs; }
    public List<MemberRef> getFieldRefs() { return fieldRefs; }
}
