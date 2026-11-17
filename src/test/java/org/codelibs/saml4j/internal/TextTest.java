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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Random;

import javax.xml.parsers.DocumentBuilderFactory;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

public class TextTest {

    // ---- safe ------------------------------------------------------------------------------------------------------

    @Test
    public void testSafeNull() {
        assertEquals("null", Text.safe(null));
    }

    @Test
    public void testSafeKeepsOrdinaryText() {
        assertEquals("", Text.safe(""));
        assertEquals("hello world", Text.safe("hello world"));
        assertEquals("café 日本語", Text.safe("café 日本語"));
    }

    @Test
    public void testSafeReplacesLineBreaks() {
        final String[] breaks = { "\r", "\n", "\u0085", " ", " ", "\r\n" };
        for (final String b : breaks) {
            final String out = Text.safe("a" + b + "b");
            assertTrue(out.startsWith("a") && out.endsWith("b"), out);
            assertFalse(out.contains("\r") || out.contains("\n") || out.contains("\u0085") || out.contains(" ") || out.contains(" "),
                    "line break survived: " + out.codePoints().boxed().toList());
            assertEquals(2 + b.length(), out.length());
        }
        assertEquals("a?b", Text.safe("a\nb"));
    }

    @Test
    public void testSafeReplacesAsciiControlCharacters() {
        for (int c = 0; c < 0x20; c++) {
            final String out = Text.safe("x" + (char) c + "y");
            assertEquals("x?y", out, "U+" + Integer.toHexString(c));
        }
        assertEquals("x?y", Text.safe("x\u007fy"));
    }

    @Test
    public void testSafeReplacesC1ControlCharacters() {
        for (int c = 0x80; c <= 0x9f; c++) {
            assertEquals("x?y", Text.safe("x" + (char) c + "y"), "U+" + Integer.toHexString(c));
        }
    }

    @Test
    public void testSafeLeavesNoIsoControlCharacter() {
        final StringBuilder all = new StringBuilder();
        for (int c = 0; c < 0x3000; c++) {
            all.append((char) c);
        }
        final String out = Text.safe(all.toString().substring(0, 200));
        out.chars().forEach(c -> assertFalse(Character.isISOControl(c), "U+" + Integer.toHexString(c)));
        for (int c = 0x80; c < 0x3000; c += 150) {
            final String one = Text.safe("<" + (char) c + ">");
            one.chars().forEach(x -> assertFalse(Character.isISOControl(x) || x == 0x2028 || x == 0x2029, "U+" + Integer.toHexString(x)));
        }
    }

    @Test
    public void testSafeBoundsLengthWithEllipsis() {
        assertEquals("a".repeat(200), Text.safe("a".repeat(200)));
        assertEquals("a".repeat(200) + "...", Text.safe("a".repeat(201)));
        assertEquals("a".repeat(200) + "...", Text.safe("a".repeat(1_000_000)));
        assertEquals(203, Text.safe("b".repeat(5000)).length());
    }

    @Test
    public void testSafeReplacesControlCharactersBeforeAndKeepsTheBound() {
        final String out = Text.safe("\n".repeat(500));
        assertEquals("?".repeat(200) + "...", out);
        final String tail = Text.safe("a".repeat(200) + "\n\n\n");
        assertEquals("a".repeat(200) + "...", tail);
    }

    @Test
    public void testSafeDoesNotCutASurrogatePairInHalf() {
        final String s = "a".repeat(199) + "😀" + "tail";
        final String out = Text.safe(s);
        for (int i = 0; i < out.length(); i++) {
            final char c = out.charAt(i);
            if (Character.isHighSurrogate(c)) {
                assertTrue(i + 1 < out.length() && Character.isLowSurrogate(out.charAt(i + 1)), "lone high surrogate at " + i);
                i++;
            } else {
                assertFalse(Character.isLowSurrogate(c), "lone low surrogate at " + i);
            }
        }
    }

    // ---- xml -------------------------------------------------------------------------------------------------------

    @Test
    public void testXmlEscapesSpecialCharacters() {
        assertEquals("&amp;&lt;&gt;&quot;&apos;", Text.xml("&<>\"'"));
        assertEquals("a&amp;amp;b", Text.xml("a&amp;b"));
        assertEquals("", Text.xml(""));
        assertEquals("plain text é日", Text.xml("plain text é日"));
    }

    @Test
    public void testXmlEscapesWhitespaceControlsAsCharacterReferences() {
        assertEquals("&#9;&#10;&#13;", Text.xml("\t\n\r"));
    }

    @Test
    public void testXmlReplacesOtherControlCharacters() {
        for (int c = 0; c < 0x20; c++) {
            if (c == '\t' || c == '\n' || c == '\r') {
                continue;
            }
            assertEquals("?", Text.xml(String.valueOf((char) c)), "U+" + Integer.toHexString(c));
        }
        assertEquals("?", Text.xml("\u007f"));
    }

    private static Document parse(final String xml) throws Exception {
        final DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(true);
        return f.newDocumentBuilder().parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void testXmlResultRoundTripsThroughAnAttribute() throws Exception {
        final String[] samples = { "&", "<script>", "\"quoted\" and 'single'", "a\tb\nc\rd", "\r\n", "&amp; &lt; &#38;", "x=\"1\" y='2'",
                "-->", "]]>", "<![CDATA[x]]>", " leading and trailing ", "日本語 😀" };
        for (final String s : samples) {
            final Document d = parse("<a v=\"" + Text.xml(s) + "\">" + Text.xml(s) + "</a>");
            assertEquals(s, d.getDocumentElement().getAttribute("v"), s);
            assertEquals(s, d.getDocumentElement().getTextContent(), s);
        }
    }

    @Test
    public void testXmlResultRoundTripsForRandomText() throws Exception {
        final Random r = new Random(20261117L);
        final String specials = "&<>\"'\t\n\r ";
        for (int i = 0; i < 500; i++) {
            final StringBuilder sb = new StringBuilder();
            final int n = r.nextInt(60);
            for (int j = 0; j < n; j++) {
                if (r.nextInt(4) == 0) {
                    sb.append(specials.charAt(r.nextInt(specials.length())));
                } else {
                    sb.appendCodePoint(randomXmlCodePoint(r));
                }
            }
            final String s = sb.toString();
            final Document d = parse("<a v=\"" + Text.xml(s) + "\" w='" + Text.xml(s) + "'>" + Text.xml(s) + "</a>");
            assertEquals(s, d.getDocumentElement().getAttribute("v"));
            assertEquals(s, d.getDocumentElement().getAttribute("w"));
            assertEquals(s, d.getDocumentElement().getTextContent());
        }
    }

    private static int randomXmlCodePoint(final Random r) {
        while (true) {
            final int cp = r.nextInt(4) == 0 ? 0x10000 + r.nextInt(0x100000) : 0x20 + r.nextInt(0xFFFD - 0x20);
            if (cp == 0x7f || cp >= 0xD800 && cp <= 0xDFFF) {
                continue;
            }
            return cp;
        }
    }

    @Test
    public void testXmlOfControlCharactersIsWellFormed() throws Exception {
        final StringBuilder all = new StringBuilder();
        for (int c = 0; c < 0x20; c++) {
            all.append((char) c);
        }
        all.append('\u007f');
        final String escaped = Text.xml(all.toString());
        parse("<a v=\"" + escaped + "\">" + escaped + "</a>");
    }

    @Test
    public void testXmlEscapedValueCannotCloseAnAttribute() throws Exception {
        final String hostile = "\" onload=\"x\" y=\"";
        final Document d = parse("<a v=\"" + Text.xml(hostile) + "\"/>");
        assertEquals(1, d.getDocumentElement().getAttributes().getLength());
        assertEquals(hostile, d.getDocumentElement().getAttribute("v"));
    }

    // ---- urlEncode / urlDecode -------------------------------------------------------------------------------------

    @Test
    public void testUrlEncodeKeepsUnreservedCharacters() {
        final String unreserved = "ABCxyz0189-._~";
        assertEquals(unreserved, Text.urlEncode(unreserved));
    }

    @Test
    public void testUrlEncodeEscapesEverythingElse() {
        assertEquals("%20", Text.urlEncode(" "));
        assertEquals("%2B", Text.urlEncode("+"));
        assertEquals("%2F%3F%23%26%3D%25", Text.urlEncode("/?#&=%"));
        assertEquals("%2A%21%27%28%29", Text.urlEncode("*!'()"));
        assertEquals("%C3%A9", Text.urlEncode("é"));
        assertEquals("%E6%97%A5", Text.urlEncode("日"));
        assertEquals("%F0%9F%98%80", Text.urlEncode("😀"));
        assertEquals("%00%0A", Text.urlEncode("\u0000\n"));
        assertEquals("", Text.urlEncode(""));
    }

    @Test
    public void testUrlEncodeUsesUpperCaseHexAndOnlyAscii() {
        final String out = Text.urlEncode("ÿþ«/");
        assertEquals("%C3%BF%C3%BE%C2%AB%2F", out);
        assertTrue(out.chars().allMatch(c -> c < 0x80));
    }

    @Test
    public void testUrlRoundTripForRandomUnicode() {
        final Random r = new Random(1117L);
        for (int i = 0; i < 3000; i++) {
            final StringBuilder sb = new StringBuilder();
            final int n = r.nextInt(40);
            for (int j = 0; j < n; j++) {
                int cp;
                do {
                    cp = switch (r.nextInt(4)) {
                    case 0 -> r.nextInt(0x80);
                    case 1 -> r.nextInt(0x800);
                    case 2 -> r.nextInt(0x10000);
                    default -> r.nextInt(0x110000);
                    };
                } while (cp >= 0xD800 && cp <= 0xDFFF);
                sb.appendCodePoint(cp);
            }
            final String s = sb.toString();
            assertEquals(s, Text.urlDecode(Text.urlEncode(s)), "iteration " + i);
        }
    }

    @Test
    public void testUrlRoundTripOfPlusPercentAndSpace() {
        final String s = "a+b%c d%2B%";
        assertEquals(s, Text.urlDecode(Text.urlEncode(s)));
    }

    @Test
    public void testUrlDecodeKeepsPlus() {
        assertEquals("a+b", Text.urlDecode("a+b"));
        assertEquals("a+b", Text.urlDecode("a%2Bb"));
        assertEquals("a+b", Text.urlDecode("a%2bb"));
        assertEquals("++", Text.urlDecode("++"));
        assertEquals("a b", Text.urlDecode("a%20b"));
    }

    @Test
    public void testUrlDecodeAcceptsEscapesAtTheEnds() {
        assertEquals("A", Text.urlDecode("%41"));
        assertEquals("xA", Text.urlDecode("x%41"));
        assertEquals("A%", Text.urlDecode("%41%25"));
        assertEquals("é", Text.urlDecode("%c3%a9"));
        assertEquals("é", Text.urlDecode("%C3%A9"));
        assertEquals("", Text.urlDecode(""));
        assertEquals("plain", Text.urlDecode("plain"));
        assertEquals("é", Text.urlDecode("é"));
    }

    @Test
    public void testUrlDecodeRefusesMalformedEscapes() {
        for (final String v : new String[] { "%", "%4", "%zz", "%4z", "%z4", "a%", "a%4", "a%zz", "%%41", "%+1", "% 1", "%-1", "%4%41",
                "100%", "%١٢" }) {
            assertNull(Text.urlDecode(v), v);
        }
    }

    @Test
    public void testUrlDecodeRefusesInvalidUtf8() {
        for (final String v : new String[] { "%FF", "%fe", "%80", "%C3", "%C3%28", "%C0%80", "%C0%AF", "%E2%82", "%ED%A0%80",
                "%F8%88%80%80%80", "%F4%90%80%80", "a%FFb", "%EF%BF" }) {
            assertNull(Text.urlDecode(v), v);
        }
    }

    @Test
    public void testUrlDecodeOfEncodedNulCharacter() {
        assertEquals("\u0000", Text.urlDecode("%00"));
    }
}
