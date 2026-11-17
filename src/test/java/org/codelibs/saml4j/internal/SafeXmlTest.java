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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.zip.Deflater;

import org.codelibs.saml4j.Reason;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class SafeXmlTest {

    private static final String NS = "urn:test";

    private static byte[] b(final String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private static Document parse(final String xml) {
        return SafeXml.parse(b(xml));
    }

    private static Reason reasonOf(final Runnable r) {
        return assertThrows(Refusal.class, r::run).reason();
    }

    private static String nested(final int depth) {
        return "<a>".repeat(depth) + "</a>".repeat(depth);
    }

    // ---- parse -----------------------------------------------------------------------------------------------------

    @Test
    public void testParseAcceptsPlainDocument() {
        final Document d = parse("<r xmlns=\"" + NS + "\" a=\"1\"><c>text</c></r>");
        assertEquals("r", d.getDocumentElement().getLocalName());
        assertEquals(NS, d.getDocumentElement().getNamespaceURI());
    }

    @Test
    public void testParseRefusesDoctypeWithoutEntities() {
        assertEquals(Reason.MALFORMED, reasonOf(() -> parse("<!DOCTYPE a><a/>")));
        assertEquals(Reason.MALFORMED, reasonOf(() -> parse("<!DOCTYPE a []><a/>")));
        assertEquals(Reason.MALFORMED,
                reasonOf(() -> parse("<?xml version=\"1.0\"?>\n<!DOCTYPE a SYSTEM \"http://127.0.0.1:1/x.dtd\"><a/>")));
    }

    @Test
    public void testParseRefusesDoctypeWithInternalEntity() {
        assertEquals(Reason.MALFORMED, reasonOf(() -> parse("<!DOCTYPE a [<!ENTITY e \"x\">]><a>&e;</a>")));
        assertEquals(Reason.MALFORMED, reasonOf(() -> parse("<!DOCTYPE a [<!ENTITY a \"x\"><!ENTITY b \"&a;&a;&a;&a;\">]><a>&b;&b;</a>")));
    }

    @Test
    public void testParseRefusesExternalEntity(@TempDir final Path dir) throws Exception {
        final Path secret = dir.resolve("secret.txt");
        Files.writeString(secret, "TOP-SECRET");
        final String xml = "<!DOCTYPE a [<!ENTITY e SYSTEM \"" + secret.toUri() + "\">]><a>&e;</a>";
        final Refusal r = assertThrows(Refusal.class, () -> parse(xml));
        assertEquals(Reason.MALFORMED, r.reason());
        assertFalse(String.valueOf(r.getMessage()).contains("TOP-SECRET"));
    }

    @Test
    public void testParseRefusesParameterEntity(@TempDir final Path dir) throws Exception {
        final Path dtd = dir.resolve("x.dtd");
        Files.writeString(dtd, "<!ENTITY % p \"x\">");
        assertEquals(Reason.MALFORMED, reasonOf(() -> parse("<!DOCTYPE a [<!ENTITY % e SYSTEM \"" + dtd.toUri() + "\"> %e;]><a/>")));
    }

    @Test
    public void testParseDoesNotExpandXInclude(@TempDir final Path dir) throws Exception {
        final Path included = dir.resolve("included.txt");
        Files.writeString(included, "INCLUDED-MARKER");
        final Document d =
                parse("<a xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include href=\"" + included.toUri() + "\" parse=\"text\"/></a>");
        assertFalse(d.getDocumentElement().getTextContent().contains("INCLUDED-MARKER"));
        final List<Element> children = SafeXml.children(d.getDocumentElement());
        assertEquals(1, children.size());
        assertEquals("include", children.get(0).getLocalName());
        assertEquals("http://www.w3.org/2001/XInclude", children.get(0).getNamespaceURI());
    }

    @Test
    public void testParseRefusesMalformedAndEmptyInput() {
        assertEquals(Reason.MALFORMED, reasonOf(() -> parse("")));
        assertEquals(Reason.MALFORMED, reasonOf(() -> parse("not xml")));
        assertEquals(Reason.MALFORMED, reasonOf(() -> parse("<a>")));
        assertEquals(Reason.MALFORMED, reasonOf(() -> parse("<a></b>")));
        assertEquals(Reason.MALFORMED, reasonOf(() -> parse("<a/><b/>")));
        assertEquals(Reason.MALFORMED, reasonOf(() -> parse("<a x=\"1\" x=\"2\"/>")));
        assertEquals(Reason.MALFORMED, reasonOf(() -> parse("<a>&undefined;</a>")));
        assertEquals(Reason.MALFORMED, reasonOf(() -> parse("<p:a/>")));
        assertEquals(Reason.MALFORMED, reasonOf(() -> SafeXml.parse(new byte[] { (byte) 0xff, (byte) 0xfe, 0x00 })));
    }

    @Test
    public void testParseAcceptsDepthOf64() {
        final Document d = parse(nested(64));
        assertNotNull(d.getDocumentElement());
    }

    @Test
    public void testParseRefusesDepthOf65() {
        assertEquals(Reason.MALFORMED, reasonOf(() -> parse(nested(65))));
    }

    @Test
    public void testParseRefusesVeryDeepNestingWithoutStackOverflow() {
        final byte[] xml = b(nested(20_000));
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> {
            final Refusal r = assertThrows(Refusal.class, () -> SafeXml.parse(xml));
            assertEquals(Reason.TOO_LARGE, r.reason());
        });
        final byte[] huge = b(nested(300_000));
        assertTimeoutPreemptively(Duration.ofSeconds(20), () -> assertThrows(Refusal.class, () -> SafeXml.parse(huge)));
    }

    @Test
    public void testParseAcceptsDepthOf64WithMixedContent() {
        final String xml = "<a>t".repeat(63) + "<b/>" + "</a>".repeat(63);
        assertDoesNotThrow(() -> parse(xml));
    }

    @Test
    public void testParseAcceptsUpToTheElementLimit() {
        final String xml = "<r>" + "<c/>".repeat(SafeXml.MAX_ELEMENTS - 1) + "</r>";
        assertEquals(SafeXml.MAX_ELEMENTS - 1, SafeXml.children(parse(xml).getDocumentElement()).size());
    }

    @Test
    public void testParseRefusesMoreThanTheElementLimit() {
        final String xml = "<r>" + "<c/>".repeat(SafeXml.MAX_ELEMENTS) + "</r>";
        assertEquals(Reason.TOO_LARGE, reasonOf(() -> parse(xml)));
    }

    @Test
    public void testParseElementLimitCountsNestedElements() {
        final String xml = "<r>" + "<c><d/><d/></c>".repeat(1667) + "</r>";
        assertEquals(Reason.TOO_LARGE, reasonOf(() -> parse(xml)));
    }

    @Test
    public void testParseAcceptsAttributeLimitOf64() {
        final StringBuilder sb = new StringBuilder("<a");
        for (int i = 0; i < 64; i++) {
            sb.append(" a").append(i).append("=\"v\"");
        }
        final Document d = parse(sb.append("/>").toString());
        assertEquals(64, d.getDocumentElement().getAttributes().getLength());
    }

    @Test
    public void testParseRefusesMoreAttributesThanTheLimit() {
        final StringBuilder sb = new StringBuilder("<a");
        for (int i = 0; i < 65; i++) {
            sb.append(" a").append(i).append("=\"v\"");
        }
        final String xml = sb.append("/>").toString();
        assertEquals(Reason.MALFORMED, reasonOf(() -> parse(xml)));
    }

    @Test
    public void testParseRefusesManyAttributesOnANestedElement() {
        final StringBuilder sb = new StringBuilder("<r><c");
        for (int i = 0; i < 1000; i++) {
            sb.append(" a").append(i).append("=\"v\"");
        }
        final String xml = sb.append("/></r>").toString();
        assertEquals(Reason.MALFORMED, reasonOf(() -> parse(xml)));
    }

    // ---- base64 ----------------------------------------------------------------------------------------------------

    @Test
    public void testBase64DecodesAndDropsWhitespace() {
        assertArrayEquals(b("hello world"), SafeXml.base64("aGVsbG8gd29ybGQ=", 100));
        assertArrayEquals(b("hello world"), SafeXml.base64("aGVs\nbG8g\r\nd29y\tbGQ=\n", 100));
        assertArrayEquals(b("hello world"), SafeXml.base64(" a G V s b G 8 g d 2 9 y b G Q = ", 100));
    }

    @Test
    public void testBase64RefusesNullAndEmpty() {
        assertEquals(Reason.MALFORMED, reasonOf(() -> SafeXml.base64(null, 100)));
        assertEquals(Reason.MALFORMED, reasonOf(() -> SafeXml.base64("", 100)));
    }

    @Test
    public void testBase64RefusesWhitespaceOnly() {
        assertEquals(Reason.MALFORMED, reasonOf(() -> SafeXml.base64("  \r\n\t ", 100)));
    }

    @Test
    public void testBase64RefusesCharactersOutsideTheAlphabet() {
        for (final String v : new String[] { "aGVs*bG8=", "aGVsbG8!", "aGVs-bG8=", "aGVs_bG8=", "aGVs bG8=", "aGVs\u000bbG8=", "aGVs\fbG8=",
                "aGVs\u0000bG8=", "éGVsbG8=", "aGVs=bG8=", "aGVsbG8=aGVsbG8=", "a", "aGVsb", "<xml/>" }) {
            assertEquals(Reason.MALFORMED, reasonOf(() -> SafeXml.base64(v, 100)), v);
        }
    }

    @Test
    public void testBase64SizeCap() {
        final byte[] ten = new byte[10];
        final byte[] eleven = new byte[11];
        assertEquals(10, SafeXml.base64(Base64.getEncoder().encodeToString(ten), 10).length);
        assertEquals(Reason.TOO_LARGE, reasonOf(() -> SafeXml.base64(Base64.getEncoder().encodeToString(eleven), 10)));
        assertEquals(Reason.TOO_LARGE, reasonOf(() -> SafeXml.base64("A".repeat(4_000_000), 100)));
        assertEquals(Reason.TOO_LARGE, reasonOf(() -> SafeXml.base64(Base64.getEncoder().encodeToString(new byte[2000]), 1999)));
        assertEquals(2000, SafeXml.base64(Base64.getEncoder().encodeToString(new byte[2000]), 2000).length);
    }

    @Test
    public void testBase64AtTheLimitIsAcceptedWhenLinesAreWrapped() {
        final byte[] payload = new byte[1000];
        new Random(1).nextBytes(payload);
        final String wrapped = Base64.getMimeEncoder(76, "\r\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(payload);
        assertArrayEquals(payload, SafeXml.base64(wrapped, 1000));
    }

    // ---- inflate ---------------------------------------------------------------------------------------------------

    private static byte[] deflate(final byte[] data) {
        final Deflater d = new Deflater(Deflater.BEST_COMPRESSION, true);
        d.setInput(data);
        d.finish();
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        final byte[] buf = new byte[1024];
        while (!d.finished()) {
            out.write(buf, 0, d.deflate(buf));
        }
        d.end();
        return out.toByteArray();
    }

    @Test
    public void testInflateRoundTrip() {
        final byte[] data = b("<samlp:AuthnRequest/>".repeat(100));
        assertArrayEquals(data, SafeXml.inflate(deflate(data), 100_000));
    }

    @Test
    public void testInflateOutputCap() {
        final byte[] data = new byte[1_000_000];
        final byte[] compressed = deflate(data);
        assertTrue(compressed.length < 5000);
        assertEquals(Reason.TOO_LARGE, reasonOf(() -> SafeXml.inflate(compressed, 1000)));
        assertEquals(Reason.TOO_LARGE, reasonOf(() -> SafeXml.inflate(compressed, 999_999)));
        assertEquals(1_000_000, SafeXml.inflate(compressed, 1_000_000).length);
        assertEquals(Reason.TOO_LARGE, reasonOf(() -> SafeXml.inflate(compressed, 0)));
    }

    @Test
    public void testInflateOutputCapAtExactBoundaryOfBufferSize() {
        for (final int size : new int[] { 4095, 4096, 4097, 8192 }) {
            final byte[] data = new byte[size];
            new Random(size).nextBytes(data);
            final byte[] compressed = deflate(data);
            assertArrayEquals(data, SafeXml.inflate(compressed, size));
            assertEquals(Reason.TOO_LARGE, reasonOf(() -> SafeXml.inflate(compressed, size - 1)));
        }
    }

    @Test
    public void testInflateRefusesTruncatedData() {
        final byte[] data = new byte[50_000];
        new Random(7).nextBytes(data);
        final byte[] compressed = deflate(data);
        assertEquals(Reason.MALFORMED,
                reasonOf(() -> SafeXml.inflate(java.util.Arrays.copyOf(compressed, compressed.length / 2), 1_000_000)));
        assertEquals(Reason.MALFORMED,
                reasonOf(() -> SafeXml.inflate(java.util.Arrays.copyOf(compressed, compressed.length - 1), 1_000_000)));
        assertEquals(Reason.MALFORMED, reasonOf(() -> SafeXml.inflate(new byte[0], 1000)));
    }

    @Test
    public void testInflateRefusesGarbage() {
        assertEquals(Reason.MALFORMED, reasonOf(() -> SafeXml.inflate(b("this is not deflate data at all, not even close"), 100_000)));
        assertEquals(Reason.MALFORMED,
                reasonOf(() -> SafeXml.inflate(new byte[] { 0x07, (byte) 0xff, (byte) 0xff, (byte) 0xff }, 100_000)));
    }

    // ---- requireUniqueIds ------------------------------------------------------------------------------------------

    @Test
    public void testUniqueIdsAreAccepted() {
        final Document d = parse("<a ID=\"_1\"><b Id=\"_2\"/><c id=\"_3\"/><d ID=\"_4\"><e Id=\"_5\"/></d></a>");
        assertDoesNotThrow(() -> SafeXml.requireUniqueIds(d));
        assertDoesNotThrow(() -> SafeXml.requireUniqueIds(parse("<a/>")));
        assertDoesNotThrow(() -> SafeXml.requireUniqueIds(parse("<a ID=\"_1\"><b ID=\"_1x\"/><b ID=\"_2\"/></a>")));
    }

    @Test
    public void testDuplicateIdsAreRefusedForEveryAttributeSpelling() {
        for (final String name : new String[] { "ID", "Id", "id" }) {
            final Document siblings = parse("<a><b " + name + "=\"x\"/><c " + name + "=\"x\"/></a>");
            assertEquals(Reason.MALFORMED, reasonOf(() -> SafeXml.requireUniqueIds(siblings)), name);
            final Document rootAndChild = parse("<a " + name + "=\"x\"><b><c " + name + "=\"x\"/></b></a>");
            assertEquals(Reason.MALFORMED, reasonOf(() -> SafeXml.requireUniqueIds(rootAndChild)), name);
        }
    }

    @Test
    public void testDuplicateIdAcrossDifferentSpellingsIsRefused() {
        assertEquals(Reason.MALFORMED, reasonOf(() -> SafeXml.requireUniqueIds(parse("<a ID=\"x\"><b id=\"x\"/></a>"))));
        assertEquals(Reason.MALFORMED, reasonOf(() -> SafeXml.requireUniqueIds(parse("<a Id=\"x\"><b ID=\"x\"/></a>"))));
        assertEquals(Reason.MALFORMED, reasonOf(() -> SafeXml.requireUniqueIds(parse("<a ID=\"x\" id=\"x\"/>"))));
    }

    @Test
    public void testDuplicateIdAtMaximumDepthIsRefused() {
        final String xml = "<a ID=\"dup\">" + "<a>".repeat(61) + "<a ID=\"dup\"/>" + "</a>".repeat(61) + "</a>";
        assertEquals(Reason.MALFORMED, reasonOf(() -> SafeXml.requireUniqueIds(parse(xml))));
    }

    // ---- plainText -------------------------------------------------------------------------------------------------

    @Test
    public void testPlainTextOfTextOnlyElement() {
        assertEquals("hello", SafeXml.plainText(parse("<a>hello</a>").getDocumentElement()));
        assertEquals("", SafeXml.plainText(parse("<a/>").getDocumentElement()));
        assertEquals(" a b ", SafeXml.plainText(parse("<a> a b </a>").getDocumentElement()));
    }

    @Test
    public void testPlainTextIsNullWithChildElements() {
        assertNull(SafeXml.plainText(parse("<a>x<b/>y</a>").getDocumentElement()));
        assertNull(SafeXml.plainText(parse("<a><b>inner</b></a>").getDocumentElement()));
        assertNull(SafeXml.plainText(parse("<a>text<b></b></a>").getDocumentElement()));
        assertNull(SafeXml.plainText(parse("<a>x<!--c--><b/></a>").getDocumentElement()));
    }

    @Test
    public void testPlainTextIgnoresCommentsAndJoinsText() {
        assertEquals("xy", SafeXml.plainText(parse("<a>x<!-- hidden -->y</a>").getDocumentElement()));
        assertEquals("", SafeXml.plainText(parse("<a><!-- only a comment --></a>").getDocumentElement()));
        assertEquals("alice@example.com", SafeXml.plainText(parse("<a>alice<!---->@example.com</a>").getDocumentElement()));
        assertEquals("a<b>c", SafeXml.plainText(parse("<a>a<![CDATA[<b>]]>c</a>").getDocumentElement()));
    }

    // ---- optionalChild / requiredChild -----------------------------------------------------------------------------

    private static final String DOC = "<r xmlns=\"" + NS + "\" xmlns:o=\"urn:other\">";

    @Test
    public void testOptionalChild() {
        final Element none = parse(DOC + "<x/></r>").getDocumentElement();
        assertNull(SafeXml.optionalChild(none, NS, "c"));
        final Element one = parse(DOC + "<c n=\"1\"/><x/></r>").getDocumentElement();
        assertEquals("1", SafeXml.optionalChild(one, NS, "c").getAttribute("n"));
        final Element two = parse(DOC + "<c n=\"1\"/><x/><c n=\"2\"/></r>").getDocumentElement();
        final Refusal r = assertThrows(Refusal.class, () -> SafeXml.optionalChild(two, NS, "c"));
        assertEquals(Reason.MALFORMED, r.reason());
    }

    @Test
    public void testRequiredChild() {
        final Element none = parse(DOC + "<x/></r>").getDocumentElement();
        assertEquals(Reason.MALFORMED, assertThrows(Refusal.class, () -> SafeXml.requiredChild(none, NS, "c")).reason());
        final Element one = parse(DOC + "<c n=\"1\"/></r>").getDocumentElement();
        assertEquals("1", SafeXml.requiredChild(one, NS, "c").getAttribute("n"));
        final Element two = parse(DOC + "<c/><c/></r>").getDocumentElement();
        assertEquals(Reason.MALFORMED, assertThrows(Refusal.class, () -> SafeXml.requiredChild(two, NS, "c")).reason());
    }

    @Test
    public void testChildLookupMatchesNamespaceAndIgnoresDescendants() {
        final Element root = parse(DOC + "<o:c/><x><c/></x></r>").getDocumentElement();
        assertNull(SafeXml.optionalChild(root, NS, "c"));
        assertNotNull(SafeXml.optionalChild(root, "urn:other", "c"));
        assertEquals(Reason.MALFORMED, assertThrows(Refusal.class, () -> SafeXml.requiredChild(root, NS, "c")).reason());
        final Element both = parse(DOC + "<o:c/><c/></r>").getDocumentElement();
        assertEquals(NS, SafeXml.requiredChild(both, NS, "c").getNamespaceURI());
        assertEquals("urn:other", SafeXml.requiredChild(both, "urn:other", "c").getNamespaceURI());
    }

    // ---- small helpers ---------------------------------------------------------------------------------------------

    @Test
    public void testChildrenIsInDocumentOrderAndSkipsText() {
        final Element root = parse(DOC + "t<a/>u<b/><!--c--><a/></r>").getDocumentElement();
        final List<Element> all = SafeXml.children(root);
        assertEquals(List.of("a", "b", "a"), all.stream().map(Element::getLocalName).toList());
        assertEquals(2, SafeXml.children(root, NS, "a").size());
        assertSame(all.get(0), SafeXml.children(root, NS, "a").get(0));
    }

    @Test
    public void testAttrAndIsAndCount() {
        final Document d = parse(DOC + "<c n=\"1\" e=\"\"/><c/></r>");
        final Element c = SafeXml.children(d.getDocumentElement()).get(0);
        assertEquals("1", SafeXml.attr(c, "n"));
        assertEquals("", SafeXml.attr(c, "e"));
        assertNull(SafeXml.attr(c, "missing"));
        assertTrue(SafeXml.is(c, NS, "c"));
        assertFalse(SafeXml.is(c, "urn:other", "c"));
        assertFalse(SafeXml.is(c, NS, "d"));
        assertEquals(2, SafeXml.count(d, NS, "c"));
        assertEquals(0, SafeXml.count(d, "urn:other", "c"));
    }
}
