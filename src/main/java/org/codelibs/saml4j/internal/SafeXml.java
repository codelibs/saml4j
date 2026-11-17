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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Deque;
import java.util.List;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.codelibs.saml4j.Reason;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.ErrorHandler;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

/**
 * Decoding and parsing of untrusted messages. Nothing here recurses on the structure of the input: the parser limits
 * the nesting depth itself, and the traversals use an explicit stack.
 */
public final class SafeXml {

    /** The deepest element nesting accepted. */
    public static final int MAX_DEPTH = 64;

    /** The most elements accepted in one document. */
    public static final int MAX_ELEMENTS = 5000;

    private static final String XML_NS = "http://www.w3.org/XML/1998/namespace";

    private static final ErrorHandler QUIET = new ErrorHandler() {
        @Override
        public void warning(final SAXParseException e) {
            // ignored
        }

        @Override
        public void error(final SAXParseException e) throws SAXException {
            throw e;
        }

        @Override
        public void fatalError(final SAXParseException e) throws SAXException {
            throw e;
        }
    };

    private SafeXml() {
    }

    /**
     * Decodes base64 text strictly: whitespace is dropped, anything else outside the alphabet is refused.
     *
     * @param text the base64 text
     * @param maxBytes the largest decoded size accepted
     * @return the decoded bytes
     */
    public static byte[] base64(final String text, final int maxBytes) {
        if (text == null || text.isEmpty()) {
            throw new Refusal(Reason.MALFORMED, "empty message");
        }
        if (text.length() > 2L * maxBytes + 1024) {
            throw new Refusal(Reason.TOO_LARGE, "message exceeds " + maxBytes + " bytes");
        }
        final StringBuilder sb = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            final char c = text.charAt(i);
            if (c != ' ' && c != '\r' && c != '\n' && c != '\t') {
                sb.append(c);
            }
        }
        if (sb.length() == 0) {
            throw new Refusal(Reason.MALFORMED, "empty message");
        }
        if (sb.length() / 4L * 3 > maxBytes + 3L) {
            throw new Refusal(Reason.TOO_LARGE, "message exceeds " + maxBytes + " bytes");
        }
        try {
            final byte[] bytes = Base64.getDecoder().decode(sb.toString());
            if (bytes.length > maxBytes) {
                throw new Refusal(Reason.TOO_LARGE, "message exceeds " + maxBytes + " bytes");
            }
            return bytes;
        } catch (final IllegalArgumentException e) {
            throw new Refusal(Reason.MALFORMED, "not base64");
        }
    }

    /**
     * Inflates raw DEFLATE data (the HTTP-Redirect encoding), refusing output larger than {@code maxBytes}.
     *
     * @param data the compressed bytes
     * @param maxBytes the largest output accepted
     * @return the inflated bytes
     */
    public static byte[] inflate(final byte[] data, final int maxBytes) {
        final Inflater inflater = new Inflater(true);
        try {
            inflater.setInput(data);
            final ByteArrayOutputStream out = new ByteArrayOutputStream(Math.min(maxBytes, data.length * 4));
            final byte[] buf = new byte[4096];
            while (!inflater.finished()) {
                final int n = inflater.inflate(buf);
                if (n == 0 && inflater.finished()) {
                    break;
                }
                if (n == 0 && (inflater.needsInput() || inflater.needsDictionary())) {
                    throw new Refusal(Reason.MALFORMED, "truncated deflate data");
                }
                if (out.size() + n > maxBytes) {
                    throw new Refusal(Reason.TOO_LARGE, "message exceeds " + maxBytes + " bytes");
                }
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } catch (final DataFormatException e) {
            throw new Refusal(Reason.MALFORMED, "not deflate data");
        } finally {
            inflater.end();
        }
    }

    /**
     * Parses a document. A DOCTYPE, external entity, XInclude, deep nesting and a huge element count are refused.
     *
     * @param xml the document bytes
     * @return the document
     */
    public static Document parse(final byte[] xml) {
        // the parser builds the whole tree before the element limit below can be checked, so bound the markup first
        int markup = 0;
        for (final byte c : xml) {
            if (c == '<' && ++markup > 4 * MAX_ELEMENTS) {
                throw new Refusal(Reason.TOO_LARGE, "document is too large or too deep");
            }
        }
        final Document doc;
        try {
            final DocumentBuilderFactory f = DocumentBuilderFactory.newDefaultInstance();
            f.setNamespaceAware(true);
            f.setXIncludeAware(false);
            f.setExpandEntityReferences(false);
            f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            f.setFeature("http://xml.org/sax/features/external-general-entities", false);
            f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            f.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
            f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            f.setAttribute("jdk.xml.maxElementDepth", Integer.toString(MAX_DEPTH));
            f.setAttribute("jdk.xml.elementAttributeLimit", "64");
            final DocumentBuilder b = f.newDocumentBuilder();
            b.setErrorHandler(QUIET);
            doc = b.parse(new InputSource(new ByteArrayInputStream(xml)));
        } catch (final SAXException e) {
            throw new Refusal(Reason.MALFORMED, "not well-formed XML");
        } catch (final java.io.IOException | javax.xml.parsers.ParserConfigurationException | IllegalArgumentException e) {
            throw new Refusal(Reason.MALFORMED, "XML could not be read");
        }
        checkShape(doc);
        return doc;
    }

    private static void checkShape(final Document doc) {
        int elements = 0;
        final Deque<Node> stack = new ArrayDeque<>();
        final Deque<Integer> depths = new ArrayDeque<>();
        stack.push(doc.getDocumentElement());
        depths.push(1);
        while (!stack.isEmpty()) {
            final Node n = stack.pop();
            final int depth = depths.pop();
            if (n.getNodeType() == Node.DOCUMENT_TYPE_NODE || n.getNodeType() == Node.ENTITY_REFERENCE_NODE) {
                throw new Refusal(Reason.MALFORMED, "DOCTYPE or entity reference");
            }
            if (n.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            if (++elements > MAX_ELEMENTS || depth > MAX_DEPTH) {
                throw new Refusal(Reason.TOO_LARGE, "document is too large or too deep");
            }
            for (Node c = n.getFirstChild(); c != null; c = c.getNextSibling()) {
                stack.push(c);
                depths.push(depth + 1);
            }
        }
    }

    /**
     * Returns the child elements of an element, in order.
     *
     * @param parent the parent
     * @return the child elements
     */
    public static List<Element> children(final Element parent) {
        final List<Element> list = new ArrayList<>();
        for (Node c = parent.getFirstChild(); c != null; c = c.getNextSibling()) {
            if (c.getNodeType() == Node.ELEMENT_NODE) {
                list.add((Element) c);
            }
        }
        return list;
    }

    /**
     * Returns the child elements with a name.
     *
     * @param parent the parent
     * @param ns the namespace
     * @param local the local name
     * @return the matching child elements
     */
    public static List<Element> children(final Element parent, final String ns, final String local) {
        final List<Element> list = new ArrayList<>();
        for (final Element e : children(parent)) {
            if (is(e, ns, local)) {
                list.add(e);
            }
        }
        return list;
    }

    /**
     * Returns the only child element with a name, {@code null} if there is none, and refuses a second one.
     *
     * @param parent the parent
     * @param ns the namespace
     * @param local the local name
     * @return the child, or {@code null}
     */
    public static Element optionalChild(final Element parent, final String ns, final String local) {
        final List<Element> list = children(parent, ns, local);
        if (list.size() > 1) {
            throw new Refusal(Reason.MALFORMED, "more than one " + local);
        }
        return list.isEmpty() ? null : list.get(0);
    }

    /**
     * Returns the only child element with a name and refuses its absence or a second one.
     *
     * @param parent the parent
     * @param ns the namespace
     * @param local the local name
     * @return the child
     */
    public static Element requiredChild(final Element parent, final String ns, final String local) {
        final Element e = optionalChild(parent, ns, local);
        if (e == null) {
            throw new Refusal(Reason.MALFORMED, "missing " + local);
        }
        return e;
    }

    /**
     * Tells whether an element has a name.
     *
     * @param e the element
     * @param ns the namespace
     * @param local the local name
     * @return {@code true} if it matches
     */
    public static boolean is(final Element e, final String ns, final String local) {
        return ns.equals(e.getNamespaceURI()) && local.equals(e.getLocalName());
    }

    /**
     * Returns the text of an element that has no child elements.
     *
     * @param e the element
     * @return the text, or {@code null} if the element has a child element
     */
    public static String plainText(final Element e) {
        final StringBuilder sb = new StringBuilder();
        for (Node c = e.getFirstChild(); c != null; c = c.getNextSibling()) {
            switch (c.getNodeType()) {
            case Node.TEXT_NODE:
            case Node.CDATA_SECTION_NODE:
                sb.append(c.getNodeValue());
                break;
            case Node.COMMENT_NODE:
                break;
            default:
                return null;
            }
        }
        return sb.toString();
    }

    /**
     * Returns the attribute value, or {@code null} when it is absent.
     *
     * @param e the element
     * @param name the attribute name (no namespace)
     * @return the value, or {@code null}
     */
    public static String attr(final Element e, final String name) {
        return e.hasAttributeNS(null, name) ? e.getAttributeNS(null, name) : null;
    }

    /**
     * Counts the elements with a name anywhere in the document.
     *
     * @param doc the document
     * @param ns the namespace
     * @param local the local name
     * @return the number of elements
     */
    public static int count(final Document doc, final String ns, final String local) {
        return doc.getElementsByTagNameNS(ns, local).getLength();
    }

    private static void requireNewId(final java.util.Set<String> seen, final String value) {
        requireValidId(value);
        if (!seen.add(value)) {
            throw new Refusal(Reason.MALFORMED, "duplicate ID");
        }
    }

    /**
     * Refuses an ID that is not a plain name: it is quoted by the XML security library when a reference fails, and
     * has no business holding a line break or any other control character.
     *
     * @param id the ID
     */
    public static void requireValidId(final String id) {
        if (id == null || !id.matches("[\\p{L}_][\\p{L}\\p{N}_.\\-]{0,255}")) {
            throw new Refusal(Reason.MALFORMED, "an ID is not a valid name");
        }
    }

    /**
     * Refuses a document in which two elements carry the same {@code ID} attribute value.
     *
     * @param doc the document
     */
    public static void requireUniqueIds(final Document doc) {
        final java.util.Set<String> seen = new java.util.HashSet<>();
        final Deque<Element> stack = new ArrayDeque<>();
        stack.push(doc.getDocumentElement());
        while (!stack.isEmpty()) {
            final Element e = stack.pop();
            for (final String name : new String[] { "ID", "Id", "id" }) {
                if (e.hasAttributeNS(null, name)) {
                    requireNewId(seen, e.getAttributeNS(null, name));
                }
            }
            if (e.hasAttributeNS(XML_NS, "id")) {
                requireNewId(seen, e.getAttributeNS(XML_NS, "id"));
            }
            stack.addAll(children(e));
        }
    }
}
