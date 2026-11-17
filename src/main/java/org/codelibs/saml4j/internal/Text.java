/*
 * Copyright 2012-2026 CodeLibs Project and the Others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */
package org.codelibs.saml4j.internal;

import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/**
 * Text helpers. Anything that came from a message and is about to reach a log goes through {@link #safe}.
 */
public final class Text {

    private static final int MAX_DETAIL = 200;

    private static final Pattern UNSAFE = Pattern.compile("[\\p{Cntrl}\\p{Cf}\\p{Co}\\p{Cs}\\u0080-\\u009f\\u2028\\u2029]");

    private Text() {
    }

    /**
     * Bounds a value and replaces every control and line-breaking character.
     *
     * @param value the value, may be {@code null}
     * @return text that is safe to put in a log line
     */
    public static String safe(final String value) {
        if (value == null) {
            return "null";
        }
        String bounded = value;
        if (value.length() > MAX_DETAIL) {
            final int cut = Character.isHighSurrogate(value.charAt(MAX_DETAIL - 1)) ? MAX_DETAIL - 1 : MAX_DETAIL;
            bounded = value.substring(0, cut) + "...";
        }
        return UNSAFE.matcher(bounded).replaceAll("?");
    }

    /**
     * Escapes text for use in XML content or in a double-quoted attribute value.
     *
     * @param value the value
     * @return the escaped value
     */
    public static String xml(final String value) {
        final StringBuilder sb = new StringBuilder(value.length() + 16);
        for (int i = 0; i < value.length(); i++) {
            final char c = value.charAt(i);
            switch (c) {
            case '&':
                sb.append("&amp;");
                break;
            case '<':
                sb.append("&lt;");
                break;
            case '>':
                sb.append("&gt;");
                break;
            case '"':
                sb.append("&quot;");
                break;
            case '\'':
                sb.append("&apos;");
                break;
            case '\t':
            case '\n':
            case '\r':
                sb.append("&#").append((int) c).append(';');
                break;
            default:
                if (Character.isHighSurrogate(c) && i + 1 < value.length() && Character.isLowSurrogate(value.charAt(i + 1))) {
                    sb.append(c).append(value.charAt(++i));
                } else if (c < 0x20 || c == 0x7f || Character.isSurrogate(c) || c == 0xfffe || c == 0xffff) {
                    sb.append('?');
                } else {
                    sb.append(c);
                }
            }
        }
        return sb.toString();
    }

    /**
     * Percent-encodes a value for a URL query (RFC 3986 unreserved characters stay as they are).
     *
     * @param value the value
     * @return the encoded value
     */
    public static String urlEncode(final String value) {
        final byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        final StringBuilder sb = new StringBuilder(bytes.length + 16);
        for (final byte b : bytes) {
            final int c = b & 0xff;
            if (c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '~') {
                sb.append((char) c);
            } else {
                sb.append('%')
                        .append(Character.toUpperCase(Character.forDigit(c >> 4, 16)))
                        .append(Character.toUpperCase(Character.forDigit(c & 0xf, 16)));
            }
        }
        return sb.toString();
    }

    /**
     * Decodes percent-escapes. A {@code +} is kept as it is, because the values decoded here are base64 or opaque
     * strings and a {@code +} is a base64 character.
     *
     * @param value the encoded value
     * @return the decoded value, or {@code null} if an escape is malformed or the bytes are not UTF-8
     */
    public static String urlDecode(final String value) {
        final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream(value.length());
        final byte[] in = value.getBytes(StandardCharsets.UTF_8);
        for (int i = 0; i < in.length; i++) {
            final int c = in[i] & 0xff;
            if (c == '%') {
                if (i + 2 >= in.length) {
                    return null;
                }
                final int hi = Character.digit(in[i + 1], 16);
                final int lo = Character.digit(in[i + 2], 16);
                if (hi < 0 || lo < 0) {
                    return null;
                }
                out.write(hi << 4 | lo);
                i += 2;
            } else {
                out.write(c);
            }
        }
        try {
            return StandardCharsets.UTF_8.newDecoder().decode(java.nio.ByteBuffer.wrap(out.toByteArray())).toString();
        } catch (final java.nio.charset.CharacterCodingException e) {
            return null;
        }
    }
}
