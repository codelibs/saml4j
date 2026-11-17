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
package org.codelibs.saml4j;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.codelibs.saml4j.internal.Names;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Helpers shared by the response tests: logging in with a fresh service provider, picking elements out of a
 * document, signing after a change, and encrypting a block of XML to the service provider.
 */
final class ResponseTestSupport {

    static final String SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256";

    static final Set<String> PENDING = Set.of("_req1");

    static final String OAEP_SHA1_METHOD = "<xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\">"
            + "<ds:DigestMethod Algorithm=\"" + Names.SHA1 + "\"/></xenc:EncryptionMethod>";

    private ResponseTestSupport() {
    }

    // ---- configuration and login -----------------------------------------------------------------------------------

    /** A configuration that can decrypt. */
    static SamlConfig.Builder configWithKey() {
        return TestIdp.config().spCertificate(TestIdp.SP_CERT).spPrivateKey(TestIdp.SP_KEY);
    }

    /** Logs in at a service provider that has never seen a message. */
    static LoginResult login(final SamlConfig.Builder config, final String encoded) {
        return ServiceProvider.create(config.build()).finishLogin(encoded, PENDING);
    }

    static LoginResult login(final String encoded) {
        return login(TestIdp.config(), encoded);
    }

    static LoginResult.Authenticated accepted(final LoginResult result) {
        return assertInstanceOf(LoginResult.Authenticated.class, result, String.valueOf(result));
    }

    static LoginResult.Rejected refused(final Reason reason, final LoginResult result) {
        final LoginResult.Rejected r = assertInstanceOf(LoginResult.Rejected.class, result, "expected " + reason + " but got " + result);
        assertEquals(reason, r.reason(), r.toString());
        return r;
    }

    /**
     * Builds the control ({@code build.apply(false)}) and checks that it is accepted, then builds the changed message
     * ({@code build.apply(true)}) and checks that it is refused with the reason.
     */
    static LoginResult.Rejected controlAndChange(final SamlConfig.Builder config, final Reason reason,
            final Function<Boolean, String> build) {
        accepted(login(config, build.apply(false)));
        return refused(reason, login(config, build.apply(true)));
    }

    static LoginResult.Rejected controlAndChange(final Reason reason, final Function<Boolean, String> build) {
        return controlAndChange(TestIdp.config(), reason, build);
    }

    // ---- documents -------------------------------------------------------------------------------------------------

    static Element first(final Document doc, final String ns, final String local) {
        return TestIdp.all(doc, ns, local).get(0);
    }

    static Element child(final Element parent, final String ns, final String local) {
        for (Node c = parent.getFirstChild(); c != null; c = c.getNextSibling()) {
            if (c instanceof Element e && ns.equals(e.getNamespaceURI()) && local.equals(e.getLocalName())) {
                return e;
            }
        }
        throw new IllegalStateException("no " + local + " in " + parent.getLocalName());
    }

    static Element response(final Document doc) {
        return doc.getDocumentElement();
    }

    static Element assertion(final Document doc) {
        return first(doc, Names.NS_SAML, "Assertion");
    }

    /** The spec's document with neither signature, so that it can still be changed. */
    static Document unsigned(final TestIdp.ResponseSpec spec) {
        spec.signResponse = false;
        spec.signAssertion = false;
        return spec.document();
    }

    static void signAssertion(final Document doc) {
        TestIdp.sign(assertion(doc), TestIdp.IDP_KEY, Names.RSA_SHA256, SHA256);
    }

    static void signResponse(final Document doc) {
        TestIdp.sign(response(doc), TestIdp.IDP_KEY, Names.RSA_SHA256, SHA256);
    }

    /** Signs the response and encodes it. */
    static String signedResponse(final Document doc) {
        signResponse(doc);
        return TestIdp.encode(doc);
    }

    /** Creates an element and declares its prefix on it, so that canonicalization sees the same namespaces as a parser. */
    static Element element(final Document doc, final String ns, final String qname) {
        final Element e = doc.createElementNS(ns, qname);
        final int colon = qname.indexOf(':');
        if (colon > 0) {
            e.setAttributeNS("http://www.w3.org/2000/xmlns/", "xmlns:" + qname.substring(0, colon), ns);
        }
        return e;
    }

    static Element signatureOf(final Element signed) {
        return child(signed, Names.NS_DS, "Signature");
    }

    /** An unsigned assertion about another subject, ready to be put into {@code doc}. */
    static Element forgedAssertion(final Document doc, final String nameId) {
        final TestIdp.ResponseSpec spec = TestIdp.response();
        spec.nameId = nameId;
        final Document other = unsigned(spec);
        return (Element) doc.importNode(assertion(other), true);
    }

    /** Appends an {@code Attribute} with values to the first AttributeStatement. */
    static void addAttribute(final Document doc, final String name, final String... values) {
        final Element statement = first(doc, Names.NS_SAML, "AttributeStatement");
        final Element attribute = element(doc, Names.NS_SAML, "saml:Attribute");
        attribute.setAttribute("Name", name);
        for (final String v : values) {
            final Element value = element(doc, Names.NS_SAML, "saml:AttributeValue");
            value.setTextContent(v);
            attribute.appendChild(value);
        }
        statement.appendChild(attribute);
    }

    // ---- encryption ------------------------------------------------------------------------------------------------

    /** A block of XML encrypted to the service provider's certificate. */
    record Encrypted(String dataAlg, String wrappedKey, String cipherValue) {

        /** The {@code EncryptedAssertion} or {@code EncryptedID} element. */
        String xml(final String wrapper, final String keyMethodXml) {
            return TestIdp.encryptedAssertionXml(dataAlg, keyMethodXml, wrappedKey, cipherValue)
                    .replace("saml:EncryptedAssertion", "saml:" + wrapper);
        }

        Element element(final String wrapper) {
            return TestIdp.parse(xml(wrapper, OAEP_SHA1_METHOD)).getDocumentElement();
        }
    }

    /** Encrypts with AES-128 in {@code cbc} or {@code gcm} mode and RSA-OAEP key transport. */
    static Encrypted encrypt(final String plain, final String mode) {
        try {
            final SecureRandom random = new SecureRandom();
            final byte[] aes = new byte[16];
            random.nextBytes(aes);
            final byte[] data;
            final String dataAlg;
            if ("gcm".equals(mode)) {
                final byte[] iv = new byte[12];
                random.nextBytes(iv);
                final Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aes, "AES"), new GCMParameterSpec(128, iv));
                data = concat(iv, c.doFinal(plain.getBytes(StandardCharsets.UTF_8)));
                dataAlg = "http://www.w3.org/2009/xmlenc11#aes128-gcm";
            } else {
                final byte[] iv = new byte[16];
                random.nextBytes(iv);
                final Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(aes, "AES"), new IvParameterSpec(iv));
                data = concat(iv, c.doFinal(plain.getBytes(StandardCharsets.UTF_8)));
                dataAlg = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
            }
            final Cipher kc = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
            kc.init(Cipher.ENCRYPT_MODE, TestIdp.SP_CERT.getPublicKey());
            return new Encrypted(dataAlg, Base64.getEncoder().encodeToString(kc.doFinal(aes)), Base64.getEncoder().encodeToString(data));
        } catch (final Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] concat(final byte[] a, final byte[] b) {
        final byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    /** The serialized assertion of an unsigned default response, as plaintext to encrypt. */
    static String plainAssertion() {
        final TestIdp.ResponseSpec spec = TestIdp.response();
        return TestIdp.serialize(assertion(unsigned(spec)));
    }

    /**
     * A response whose assertion is replaced by {@code encrypted}, signed afterwards so that the response signature
     * covers the encrypted block as it is.
     */
    static Document responseWithEncryptedAssertion(final Element encrypted, final boolean signResponse) {
        final Document doc = unsigned(TestIdp.response());
        final Element imported = (Element) doc.importNode(encrypted, true);
        response(doc).replaceChild(imported, assertion(doc));
        if (signResponse) {
            signResponse(doc);
        }
        return doc;
    }

    // ---- hostile-input helpers -------------------------------------------------------------------------------------

    /** A local listener that counts connections: nothing the library does with a message may reach it. */
    static final class Canary implements AutoCloseable {

        private final ServerSocket server;

        private final AtomicInteger hits = new AtomicInteger();

        Canary() {
            try {
                server = new ServerSocket(0, 5, InetAddress.getLoopbackAddress());
            } catch (final IOException e) {
                throw new IllegalStateException(e);
            }
            final Thread t = new Thread(() -> {
                while (!server.isClosed()) {
                    try (java.net.Socket s = server.accept()) {
                        hits.incrementAndGet();
                    } catch (final IOException e) {
                        break;
                    }
                }
            }, "canary");
            t.setDaemon(true);
            t.start();
        }

        String url(final String path) {
            return "http://127.0.0.1:" + server.getLocalPort() + path;
        }

        int hits() {
            try {
                Thread.sleep(200);
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return hits.get();
        }

        @Override
        public void close() {
            try {
                server.close();
            } catch (final IOException e) {
                // ignored
            }
        }
    }

    /** Collects what reaches the {@code java.util.logging} root logger (and so what System.Logger users write). */
    static final class LogCapture implements AutoCloseable {

        private final Logger root = Logger.getLogger("");

        private final List<LogRecord> records = new CopyOnWriteArrayList<>();

        private final Handler handler = new Handler() {
            @Override
            public void publish(final LogRecord r) {
                records.add(r);
            }

            @Override
            public void flush() {
            }

            @Override
            public void close() {
            }
        };

        private final Level previous = root.getLevel();

        LogCapture() {
            handler.setLevel(Level.ALL);
            root.setLevel(Level.ALL);
            root.addHandler(handler);
        }

        int size() {
            return records.size();
        }

        /** Everything at or above a level, with parameters and the messages of the throwable chain, as one text. */
        String text(final Level min) {
            final StringBuilder sb = new StringBuilder();
            for (final LogRecord r : records) {
                if (r.getLevel().intValue() < min.intValue()) {
                    continue;
                }
                sb.append(r.getLoggerName()).append(' ').append(r.getMessage());
                if (r.getParameters() != null) {
                    for (final Object p : r.getParameters()) {
                        sb.append(' ').append(p);
                    }
                }
                for (Throwable t = r.getThrown(); t != null; t = t.getCause()) {
                    sb.append(' ').append(t);
                }
                sb.append('\n');
            }
            return sb.toString();
        }

        @Override
        public void close() {
            root.removeHandler(handler);
            root.setLevel(previous);
        }
    }
}
