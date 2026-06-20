package io.sloptropy.ghidra.mcp.api;

import java.util.Map;

/**
 * Minimal JSON writer for tool result payloads.
 *
 * Tools build their response shape as nested Map / Iterable / String /
 * Number / Boolean / null and call {@link #render(Object)} to serialize.
 * Keeps tool code free of JSON-library imports and avoids threading a
 * Jackson writer through MCP's text-content shape (which expects a
 * fully-rendered String).
 *
 * Handles the shapes the tool payloads need; not a general-purpose JSON
 * library. Notably: no number-special-case handling (NaN/Infinity), no
 * date types, no custom serializers.
 */
public final class JsonRender {

    private JsonRender() {}

    public static String render(Object o) {
        StringBuilder sb = new StringBuilder(256);
        write(sb, o);
        return sb.toString();
    }

    private static void write(StringBuilder sb, Object o) {
        if (o == null) { sb.append("null"); return; }
        if (o instanceof String s) { writeString(sb, s); return; }
        if (o instanceof Number || o instanceof Boolean) {
            sb.append(o.toString());
            return;
        }
        if (o instanceof Map<?, ?> m) {
            sb.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> e : m.entrySet()) {
                if (!first) sb.append(',');
                first = false;
                writeString(sb, e.getKey().toString());
                sb.append(':');
                write(sb, e.getValue());
            }
            sb.append('}');
            return;
        }
        if (o instanceof Iterable<?> it) {
            sb.append('[');
            boolean first = true;
            for (Object x : it) {
                if (!first) sb.append(',');
                first = false;
                write(sb, x);
            }
            sb.append(']');
            return;
        }
        writeString(sb, o.toString());
    }

    private static void writeString(StringBuilder sb, String s) {
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                case '\b': sb.append("\\b");  break;
                case '\f': sb.append("\\f");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        sb.append('"');
    }
}
