package com.rawtcp.burp.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Lossless form projection: only edited components are re-encoded. No stream reassembly. */
public final class FormBody {
    private static final Pattern LENGTH = Pattern.compile("(?im)^(Content-Length:[ \\t]*)([0-9]+)([ \\t]*\\r?)$");
    private final String headers;
    private final List<Field> fields;
    /** Trailing line break kept outside the fields (paste artifact on bare forms). */
    private final String suffix;

    public record Field(String rawName, String rawValue, boolean equalsSign, String name, String value) {
        String wire() { return rawName + (equalsSign ? "=" + rawValue : ""); }
    }

    private FormBody(String headers, List<Field> fields) {
        this(headers, fields, "");
    }

    private FormBody(String headers, List<Field> fields, String suffix) {
        this.headers = headers;
        this.fields = List.copyOf(fields);
        this.suffix = suffix;
    }

    public static FormBody parse(byte[] bytes) {
        if (bytes.length > 65_536) throw new IllegalArgumentException("Parameter view supports up to 64 KiB");
        String source = UrlCodec.text(bytes);
        // Pasted requests often use LF-only line endings; accept both styles
        // but always rebuild with the original one.
        String eol = source.contains("\r\n") ? "\r\n" : "\n";
        String headers = "";
        String body = source;
        String suffix = "";
        int boundary = source.indexOf(eol + eol);
        boolean http = source.startsWith("HTTP/1.") || source.matches("(?s)^[A-Z]+ [^\\r\\n]+ HTTP/1\\.[01].*");
        if (http) {
            if (boundary < 0) throw new IllegalArgumentException("HTTP headers incomplete: no blank line after headers");
            headers = source.substring(0, boundary + eol.length() * 2);
            body = source.substring(boundary + eol.length() * 2);
            String type = null;
            int lengths = 0;
            for (String line : headers.split(eol)) {
                if (line.startsWith(" ") || line.startsWith("\t"))
                    throw new IllegalArgumentException("Folded HTTP headers: edit raw bytes instead");
                int colon = line.indexOf(':');
                if (colon < 0) continue;
                String name = line.substring(0, colon).trim().toLowerCase(Locale.ROOT);
                String value = line.substring(colon + 1).trim().toLowerCase(Locale.ROOT);
                if (name.equals("content-length")) lengths++;
                if (name.equals("transfer-encoding") || name.equals("content-encoding") && !value.equals("identity"))
                    throw new IllegalArgumentException("Encoded/chunked HTTP body: edit raw bytes instead");
                if (name.equals("content-type")) {
                    if (type != null) throw new IllegalArgumentException("Ambiguous Content-Type");
                    type = value;
                }
            }
            if (type == null || !type.split(";", 2)[0].trim().equals("application/x-www-form-urlencoded"))
                throw new IllegalArgumentException("Body is not application/x-www-form-urlencoded");
            for (String parameter : type.split(";")) {
                String[] parts = parameter.trim().split("=", 2);
                if (parts[0].trim().equals("charset")
                        && (parts.length != 2 || !parts[1].trim().replace("\"", "").equals("utf-8")))
                    throw new IllegalArgumentException("Parameter editing requires UTF-8");
            }
            Matcher length = LENGTH.matcher(headers);
            if (lengths != 1 || !length.find()) throw new IllegalArgumentException("One complete HTTP Content-Length body required");
            long expected;
            try { expected = Long.parseLong(length.group(2)); }
            catch (NumberFormatException error) { throw new IllegalArgumentException("Invalid Content-Length"); }
            if (length.find() || expected != UrlCodec.utf8(body).length)
                throw new IllegalArgumentException("Partial or multiple HTTP messages: edit raw bytes instead");
        } else {
            if (body.endsWith(eol)) {
                // One trailing line break is usually a paste artifact, not a field.
                suffix = eol;
                body = body.substring(0, body.length() - eol.length());
            }
            if (boundary >= 0 || body.indexOf('\r') >= 0 || body.indexOf('\n') >= 0) {
                throw new IllegalArgumentException("No form body detected in this chunk");
            }
        }
        if (!body.contains("=")) throw new IllegalArgumentException("No name=value body parameters detected");
        if (body.chars().anyMatch(c -> c > 127))
            throw new IllegalArgumentException("No form body detected in this chunk");
        String[] parts = body.split("&", -1);
        if (parts.length > 512) throw new IllegalArgumentException("Parameter view supports up to 512 fields");
        List<Field> fields = new ArrayList<>();
        for (String part : parts) {
            int equals = part.indexOf('=');
            String rawName = equals < 0 ? part : part.substring(0, equals);
            String rawValue = equals < 0 ? "" : part.substring(equals + 1);
            if (!rawName.matches("[A-Za-z0-9_. $~%+\\[\\]-]*")
                    || part.chars().anyMatch(c -> c < 32 || c == 127))
                throw new IllegalArgumentException("No form body detected in this chunk");
            fields.add(new Field(rawName, rawValue, equals >= 0,
                    UrlCodec.decode(rawName, true), UrlCodec.decode(rawValue, true)));
        }
        return new FormBody(headers, fields, suffix);
    }

    public List<Field> fields() { return fields; }
    public boolean isHttp() { return !headers.isEmpty(); }

    public FormBody edit(int row, String name, String value) {
        List<Field> next = new ArrayList<>(fields);
        Field field = next.get(row);
        String key = name.equals(field.name()) ? field.rawName() : encodeLike(name, field.rawName());
        String val = value.equals(field.value()) ? field.rawValue() : encodeLike(value, field.rawValue());
        next.set(row, new Field(key, val, field.equalsSign() || !value.isEmpty(), name, value));
        return new FormBody(headers, next, suffix);
    }

    private static String encodeLike(String text, String previous) {
        return UrlCodec.encode(text, !previous.contains("%20"));
    }

    public byte[] bytes() {
        String body = String.join("&", fields.stream().map(Field::wire).toList());
        String prefix = headers;
        if (!prefix.isEmpty()) {
            Matcher length = LENGTH.matcher(prefix);
            if (length.find() && Long.parseLong(length.group(2)) != UrlCodec.utf8(body).length) {
                prefix = prefix.substring(0, length.start(2)) + UrlCodec.utf8(body).length + prefix.substring(length.end(2));
            }
        }
        return UrlCodec.utf8(prefix + body + suffix);
    }
}
