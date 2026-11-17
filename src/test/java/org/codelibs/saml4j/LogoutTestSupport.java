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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.Inflater;

import org.codelibs.saml4j.LogoutOutcome.Action;
import org.codelibs.saml4j.internal.Names;
import org.codelibs.saml4j.internal.Text;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Helpers shared by the logout, redirect-binding and outgoing-message tests.
 */
final class LogoutTestSupport {

    /** The user of the session that the tests try to end. */
    static final String USER = "alice@example.com";

    /** The SessionIndex of that session. */
    static final String INDEX = "_session1";

    private static final Pattern MESSAGE_PARAM = Pattern.compile("([?&])(SAMLRequest|SAMLResponse)=");

    private LogoutTestSupport() {
    }

    static ServiceProvider sp() {
        return ServiceProvider.create(TestIdp.configWithLogout().build());
    }

    static ServiceProvider sp(final SamlConfig.Builder builder) {
        return ServiceProvider.create(builder.build());
    }

    /** A service provider that also accepts unsigned logout messages. */
    static ServiceProvider spAcceptingUnsigned() {
        return sp(TestIdp.configWithLogout().wantLogoutSigned(false));
    }

    static LogoutOutcome handle(final ServiceProvider sp, final String query) {
        return sp.handleLogout("GET", query, USER, INDEX);
    }

    /**
     * Builds the query string of a redirect-binding message, signed with the given key (or unsigned if the key is
     * {@code null}). The signature covers {@code message[&RelayState]&SigAlg}, as the binding says.
     * (TestIdp.redirectQuery appends {@code &Signature=} before it takes the string to sign, so it cannot be used.)
     */
    static String redirectQuery(final String param, final String xml, final String relayState, final java.security.PrivateKey key) {
        final StringBuilder q = new StringBuilder(param).append('=').append(Text.urlEncode(TestIdp.deflate(xml)));
        if (relayState != null) {
            q.append("&RelayState=").append(Text.urlEncode(relayState));
        }
        if (key != null) {
            q.append("&SigAlg=").append(Text.urlEncode(Names.RSA_SHA256));
            final String signature = TestIdp.rsaSign(q.toString(), key, "SHA256withRSA");
            q.append("&Signature=").append(Text.urlEncode(signature));
        }
        return q.toString();
    }

    // ---- outcome assertions ----------------------------------------------------------------------------------------

    /** Asserts that the session is to be ended and the browser sent back with an answer. */
    static void assertEnded(final LogoutOutcome o) {
        assertEquals(Action.END_SESSION, o.action(), o.toString());
        assertNull(o.reason(), o.toString());
        assertNotNull(o.redirectUrl(), o.toString());
        assertNotNull(o.detail());
    }

    /** Asserts that the session is kept, and the browser sent back with an answer. */
    static void assertKeptAndAnswered(final LogoutOutcome o) {
        assertEquals(Action.KEEP_SESSION, o.action(), o.toString());
        assertNull(o.reason(), o.toString());
        assertNotNull(o.redirectUrl(), o.toString());
        assertNotNull(o.detail());
    }

    /** Asserts that the message was refused for one specific reason, with no redirect. */
    static void assertRejected(final Reason reason, final LogoutOutcome o) {
        assertEquals(Action.REJECTED, o.action(), o.toString());
        assertEquals(reason, o.reason(), o.toString());
        assertNull(o.redirectUrl(), o.toString());
        assertNotNull(o.detail());
    }

    // ---- an incoming LogoutRequest ---------------------------------------------------------------------------------

    /** A LogoutRequest from the IdP with every part adjustable; the defaults are acceptable. */
    static final class Request {

        String id = "_lr1";

        /** {@code null} leaves the Issuer element out. */
        String issuer = TestIdp.IDP;

        /** {@code null} leaves the attribute out. */
        String destination = TestIdp.SLS;

        String issueInstant = TestIdp.NOW.toString();

        /** {@code null} leaves the attribute out. */
        String notOnOrAfter;

        String version = "2.0";

        String nameId = USER;

        List<String> sessionIndexes = List.of(INDEX);

        Request() {
        }

        Request(final String id) {
            this.id = id;
        }

        Request id(final String v) {
            id = v;
            return this;
        }

        Request nameId(final String v) {
            nameId = v;
            return this;
        }

        Request sessionIndexes(final String... v) {
            sessionIndexes = List.of(v);
            return this;
        }

        String xml() {
            final StringBuilder sb = new StringBuilder(512);
            sb.append("<samlp:LogoutRequest xmlns:samlp=\"")
                    .append(Names.NS_SAMLP)
                    .append("\" xmlns:saml=\"")
                    .append(Names.NS_SAML)
                    .append('"');
            if (id != null) {
                sb.append(" ID=\"").append(Text.xml(id)).append('"');
            }
            if (version != null) {
                sb.append(" Version=\"").append(Text.xml(version)).append('"');
            }
            sb.append(" IssueInstant=\"").append(issueInstant).append('"');
            if (notOnOrAfter != null) {
                sb.append(" NotOnOrAfter=\"").append(notOnOrAfter).append('"');
            }
            if (destination != null) {
                sb.append(" Destination=\"").append(Text.xml(destination)).append('"');
            }
            sb.append('>');
            if (issuer != null) {
                sb.append("<saml:Issuer>").append(Text.xml(issuer)).append("</saml:Issuer>");
            }
            if (nameId != null) {
                sb.append("<saml:NameID>").append(Text.xml(nameId)).append("</saml:NameID>");
            }
            for (final String s : sessionIndexes) {
                sb.append("<samlp:SessionIndex>").append(Text.xml(s)).append("</samlp:SessionIndex>");
            }
            return sb.append("</samlp:LogoutRequest>").toString();
        }

        /** The query string as the IdP would send it, signed with the IdP key. */
        String signed() {
            return LogoutTestSupport.redirectQuery("SAMLRequest", xml(), null, TestIdp.IDP_KEY);
        }

        String signed(final String relayState) {
            return LogoutTestSupport.redirectQuery("SAMLRequest", xml(), relayState, TestIdp.IDP_KEY);
        }

        String unsigned() {
            return LogoutTestSupport.redirectQuery("SAMLRequest", xml(), null, null);
        }
    }

    // ---- an outgoing message ---------------------------------------------------------------------------------------

    /** The URL of a message this library sent, taken apart. */
    static final class Sent {

        /** The endpoint, without the message parameters. */
        final String endpoint;

        /** The separator that was put between the endpoint and the parameters. */
        final char separator;

        /** The parameters, raw (still percent-encoded), in the order they appear. */
        final Map<String, String> raw = new LinkedHashMap<>();

        private final String query;

        private Sent(final String url) {
            final Matcher m = MESSAGE_PARAM.matcher(url);
            if (!m.find()) {
                throw new AssertionError("no SAMLRequest or SAMLResponse in " + url);
            }
            endpoint = url.substring(0, m.start());
            separator = url.charAt(m.start());
            query = url.substring(m.start() + 1);
            for (final String pair : query.split("&")) {
                final int eq = pair.indexOf('=');
                if (raw.put(pair.substring(0, eq), pair.substring(eq + 1)) != null) {
                    throw new AssertionError("duplicate parameter in " + url);
                }
            }
        }

        static Sent parse(final String url) {
            return new Sent(url);
        }

        String messageName() {
            return raw.containsKey("SAMLRequest") ? "SAMLRequest" : "SAMLResponse";
        }

        /** The percent-decoded value of a parameter, or {@code null}. */
        String param(final String name) {
            final String r = raw.get(name);
            return r == null ? null : Text.urlDecode(r);
        }

        /** The XML text of the message. */
        String xml() {
            final byte[] deflated = Base64.getDecoder().decode(param(messageName()));
            final Inflater inflater = new Inflater(true);
            try {
                inflater.setInput(deflated);
                final ByteArrayOutputStream out = new ByteArrayOutputStream();
                final byte[] buf = new byte[4096];
                while (!inflater.finished()) {
                    final int n = inflater.inflate(buf);
                    if (n == 0 && inflater.needsInput()) {
                        throw new AssertionError("truncated deflate data");
                    }
                    out.write(buf, 0, n);
                }
                return out.toString(StandardCharsets.UTF_8);
            } catch (final java.util.zip.DataFormatException e) {
                throw new AssertionError(e);
            } finally {
                inflater.end();
            }
        }

        Document document() {
            return TestIdp.parse(xml());
        }

        /** The string the signature is computed over: everything before {@code &Signature=}. */
        String signedString() {
            final int i = query.indexOf("&Signature=");
            return i < 0 ? query : query.substring(0, i);
        }

        /** Tells whether the message carries a signature that verifies with the certificate. */
        boolean signatureVerifies(final X509Certificate cert) {
            final String alg = param("SigAlg");
            final String sig = param("Signature");
            if (alg == null || sig == null) {
                return false;
            }
            final String jca = switch (alg) {
            case Names.RSA_SHA256 -> "SHA256withRSA";
            case Names.RSA_SHA384 -> "SHA384withRSA";
            case Names.RSA_SHA512 -> "SHA512withRSA";
            default -> throw new AssertionError("unexpected SigAlg " + alg);
            };
            try {
                final Signature s = Signature.getInstance(jca);
                s.initVerify(cert.getPublicKey());
                s.update(signedString().getBytes(StandardCharsets.UTF_8));
                return s.verify(Base64.getDecoder().decode(sig));
            } catch (final java.security.GeneralSecurityException e) {
                throw new AssertionError(e);
            }
        }
    }

    static Sent sent(final String url) {
        return Sent.parse(url);
    }

    // ---- reading XML -----------------------------------------------------------------------------------------------

    /** The only element with the name anywhere in the document. */
    static Element only(final Document doc, final String ns, final String local) {
        final List<Element> list = TestIdp.all(doc, ns, local);
        assertEquals(1, list.size(), local + " occurs " + list.size() + " times");
        return list.get(0);
    }

    static String text(final Document doc, final String ns, final String local) {
        return only(doc, ns, local).getTextContent();
    }
}
