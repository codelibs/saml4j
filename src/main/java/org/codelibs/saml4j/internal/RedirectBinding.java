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
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.zip.Deflater;

import org.codelibs.saml4j.Reason;

/**
 * The HTTP-Redirect binding: parsing the raw query of an incoming message, checking its signature, and building
 * the URL of an outgoing one.
 *
 * <p>The signed string is built from the same raw values that the message is decoded from, and a name that occurs
 * twice is refused, so the bytes that were signed and the bytes that are used cannot differ.</p>
 */
public final class RedirectBinding {

    private static final Set<String> NAMES = Set.of("SAMLRequest", "SAMLResponse", "RelayState", "SigAlg", "Signature");

    private RedirectBinding() {
    }

    /** The relevant parameters of a query, as they were received (still percent-encoded). */
    public static final class Query {

        private final Map<String, String> raw;

        private Query(final Map<String, String> raw) {
            this.raw = raw;
        }

        /**
         * Returns the raw value of a parameter.
         *
         * @param name the parameter name
         * @return the raw value, or {@code null}
         */
        public String raw(final String name) {
            return raw.get(name);
        }

        /**
         * Returns the percent-decoded value of a parameter.
         *
         * @param name the parameter name
         * @return the decoded value, or {@code null} if it is absent
         */
        public String decoded(final String name) {
            final String r = raw.get(name);
            if (r == null) {
                return null;
            }
            final String d = Text.urlDecode(r);
            if (d == null) {
                throw new Refusal(Reason.BAD_REQUEST, name + " is not correctly encoded");
            }
            return d;
        }
    }

    /**
     * Parses a raw query string. Parameter names are compared after percent-decoding, exactly; a relevant name that
     * occurs more than once is refused.
     *
     * @param rawQuery the query string as received, without the leading {@code ?}
     * @param maxLength the longest query accepted
     * @return the parsed query
     */
    public static Query parse(final String rawQuery, final int maxLength) {
        if (rawQuery == null || rawQuery.isEmpty()) {
            throw new Refusal(Reason.BAD_REQUEST, "no query string");
        }
        if (rawQuery.length() > maxLength) {
            throw new Refusal(Reason.TOO_LARGE, "query string is too long");
        }
        final Map<String, String> raw = new HashMap<>();
        for (final String pair : rawQuery.split("&", -1)) {
            if (pair.isEmpty()) {
                continue;
            }
            final int eq = pair.indexOf('=');
            final String rawName = eq < 0 ? pair : pair.substring(0, eq);
            final String name = Text.urlDecode(rawName);
            if (name == null) {
                throw new Refusal(Reason.BAD_REQUEST, "a parameter name is not correctly encoded");
            }
            if (!NAMES.contains(name)) {
                continue;
            }
            if (raw.put(name, eq < 0 ? "" : pair.substring(eq + 1)) != null) {
                throw new Refusal(Reason.BAD_REQUEST, name + " occurs more than once");
            }
        }
        return new Query(raw);
    }

    /**
     * Checks the query signature, if there is one.
     *
     * @param q the parsed query
     * @param messageName {@code SAMLRequest} or {@code SAMLResponse}
     * @param certs the certificates that may sign
     * @param allowDeprecated whether SHA-1 is accepted
     * @return {@code true} if the message is signed and the signature verifies, {@code false} if it carries no
     *         signature
     * @throws Refusal if a signature is present and does not verify
     */
    public static boolean verify(final Query q, final String messageName, final List<X509Certificate> certs,
            final boolean allowDeprecated) {
        final String sig = q.raw("Signature");
        final String alg = q.raw("SigAlg");
        if (sig == null && alg == null) {
            return false;
        }
        if (sig == null || alg == null) {
            throw new Refusal(Reason.BAD_REQUEST, "Signature and SigAlg must be given together");
        }
        final String algUri = q.decoded("SigAlg");
        final String jca = jcaName(algUri, allowDeprecated);
        if (jca == null) {
            throw new Refusal(Reason.INVALID_SIGNATURE, "signature algorithm is not allowed: " + Text.safe(algUri));
        }
        final byte[] signature;
        try {
            signature = Base64.getDecoder().decode(q.decoded("Signature").replaceAll("\\s", ""));
        } catch (final IllegalArgumentException e) {
            throw new Refusal(Reason.INVALID_SIGNATURE, "signature is not base64");
        }
        final StringBuilder signed = new StringBuilder(messageName).append('=').append(q.raw(messageName));
        if (q.raw("RelayState") != null) {
            signed.append("&RelayState=").append(q.raw("RelayState"));
        }
        signed.append("&SigAlg=").append(alg);
        final byte[] data = signed.toString().getBytes(StandardCharsets.UTF_8);
        for (final X509Certificate cert : certs) {
            try {
                final Signature s = Signature.getInstance(jca);
                s.initVerify(cert.getPublicKey());
                s.update(data);
                if (s.verify(signature)) {
                    return true;
                }
            } catch (final GeneralSecurityException e) {
                // not this certificate
                continue;
            }
        }
        throw new Refusal(Reason.INVALID_SIGNATURE, "signature does not verify");
    }

    private static String jcaName(final String uri, final boolean allowDeprecated) {
        if (Names.RSA_SHA256.equals(uri)) {
            return "SHA256withRSA";
        }
        if (Names.RSA_SHA384.equals(uri)) {
            return "SHA384withRSA";
        }
        if (Names.RSA_SHA512.equals(uri)) {
            return "SHA512withRSA";
        }
        if (allowDeprecated && Names.RSA_SHA1.equals(uri)) {
            return "SHA1withRSA";
        }
        return null;
    }

    /**
     * Decodes the message parameter: percent-decoding, base64, inflate.
     *
     * @param q the parsed query
     * @param messageName the parameter name
     * @param maxBytes the largest message accepted
     * @return the XML bytes
     */
    public static byte[] decodeMessage(final Query q, final String messageName, final int maxBytes) {
        final String value = q.decoded(messageName);
        return SafeXml.inflate(SafeXml.base64(value, maxBytes), maxBytes);
    }

    /**
     * Builds the URL of an outgoing message.
     *
     * @param endpoint the URL of the receiving endpoint
     * @param messageName {@code SAMLRequest} or {@code SAMLResponse}
     * @param xml the message
     * @param relayState the RelayState to send, or {@code null}
     * @param key the key to sign with, or {@code null} for no signature
     * @param sigAlg the signature algorithm URI, used when {@code key} is given
     * @return the URL
     */
    public static String build(final String endpoint, final String messageName, final String xml, final String relayState,
            final PrivateKey key, final String sigAlg) {
        final StringBuilder query = new StringBuilder(messageName).append('=').append(Text.urlEncode(deflate(xml)));
        if (relayState != null && !relayState.isEmpty()) {
            query.append("&RelayState=").append(Text.urlEncode(relayState));
        }
        if (key != null) {
            query.append("&SigAlg=").append(Text.urlEncode(sigAlg));
            final String jca = jcaName(sigAlg, false);
            try {
                final Signature s = Signature.getInstance(jca);
                s.initSign(key);
                s.update(query.toString().getBytes(StandardCharsets.UTF_8));
                query.append("&Signature=").append(Text.urlEncode(Base64.getEncoder().encodeToString(s.sign())));
            } catch (final GeneralSecurityException e) {
                throw new IllegalStateException("the message could not be signed", e);
            }
        }
        return endpoint + (endpoint.contains("?") ? "&" : "?") + query;
    }

    private static String deflate(final String xml) {
        final Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION, true);
        try {
            deflater.setInput(xml.getBytes(StandardCharsets.UTF_8));
            deflater.finish();
            final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            final byte[] buf = new byte[4096];
            while (!deflater.finished()) {
                out.write(buf, 0, deflater.deflate(buf));
            }
            return Base64.getEncoder().encodeToString(out.toByteArray());
        } finally {
            deflater.end();
        }
    }
}
