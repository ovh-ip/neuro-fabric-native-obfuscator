package dev.hydro.j2c.fabric;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Minimal zero-dependency JSON parser for fabric.mod.json and *.mixins.json.
 */
public final class MiniJson {
    private final String src;
    private int pos;

    private MiniJson(String src) {
        this.src = src;
    }

    public static Object parse(String json) {
        MiniJson p = new MiniJson(json);
        p.skipWs();
        Object val = p.readValue();
        return val;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> parseObject(String json) {
        Object o = parse(json);
        return o instanceof Map ? (Map<String, Object>) o : Map.of();
    }

    private Object readValue() {
        skipWs();
        if (pos >= src.length()) throw new IllegalArgumentException("Unexpected end of JSON");
        char c = src.charAt(pos);
        return switch (c) {
            case '{' -> readObject();
            case '[' -> readArray();
            case '"' -> readString();
            case 't', 'f' -> readBoolean();
            case 'n' -> readNull();
            default -> readNumber();
        };
    }

    private Map<String, Object> readObject() {
        pos++; // '{'
        Map<String, Object> map = new LinkedHashMap<>();
        skipWs();
        if (pos < src.length() && src.charAt(pos) == '}') {
            pos++;
            return map;
        }
        while (pos < src.length()) {
            skipWs();
            String key = readString();
            skipWs();
            expect(':');
            Object val = readValue();
            map.put(key, val);
            skipWs();
            if (pos < src.length() && src.charAt(pos) == ',') {
                pos++;
            } else if (pos < src.length() && src.charAt(pos) == '}') {
                pos++;
                return map;
            } else {
                throw new IllegalArgumentException("Expected ',' or '}' at pos " + pos);
            }
        }
        throw new IllegalArgumentException("Unterminated object");
    }

    private List<Object> readArray() {
        pos++; // '['
        List<Object> list = new ArrayList<>();
        skipWs();
        if (pos < src.length() && src.charAt(pos) == ']') {
            pos++;
            return list;
        }
        while (pos < src.length()) {
            list.add(readValue());
            skipWs();
            if (pos < src.length() && src.charAt(pos) == ',') {
                pos++;
            } else if (pos < src.length() && src.charAt(pos) == ']') {
                pos++;
                return list;
            } else {
                throw new IllegalArgumentException("Expected ',' or ']' at pos " + pos);
            }
        }
        throw new IllegalArgumentException("Unterminated array");
    }

    private String readString() {
        expect('"');
        StringBuilder sb = new StringBuilder();
        while (pos < src.length()) {
            char c = src.charAt(pos++);
            if (c == '"') return sb.toString();
            if (c == '\\') {
                if (pos >= src.length()) break;
                char esc = src.charAt(pos++);
                switch (esc) {
                    case '"', '\\', '/' -> sb.append(esc);
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case 'n' -> sb.append('\n');
                    case 'r' -> sb.append('\r');
                    case 't' -> sb.append('\t');
                    case 'u' -> {
                        String hex = src.substring(pos, pos + 4);
                        pos += 4;
                        sb.append((char) Integer.parseInt(hex, 16));
                    }
                    default -> sb.append(esc);
                }
            } else {
                sb.append(c);
            }
        }
        throw new IllegalArgumentException("Unterminated string");
    }

    private Boolean readBoolean() {
        if (src.startsWith("true", pos)) { pos += 4; return Boolean.TRUE; }
        if (src.startsWith("false", pos)) { pos += 5; return Boolean.FALSE; }
        throw new IllegalArgumentException("Invalid boolean at pos " + pos);
    }

    private Object readNull() {
        if (src.startsWith("null", pos)) { pos += 4; return null; }
        throw new IllegalArgumentException("Invalid null at pos " + pos);
    }

    private Number readNumber() {
        int start = pos;
        boolean isFloat = false;
        if (src.charAt(pos) == '-') pos++;
        while (pos < src.length()) {
            char c = src.charAt(pos);
            if (c >= '0' && c <= '9') pos++;
            else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') { isFloat = true; pos++; }
            else break;
        }
        String raw = src.substring(start, pos);
        return isFloat ? Double.parseDouble(raw) : Long.parseLong(raw);
    }

    private void expect(char expected) {
        if (pos >= src.length() || src.charAt(pos) != expected) {
            throw new IllegalArgumentException("Expected '" + expected + "' at pos " + pos);
        }
        pos++;
    }

    private void skipWs() {
        while (pos < src.length()) {
            char c = src.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos++;
            else break;
        }
    }
}
