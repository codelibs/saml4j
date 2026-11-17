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
import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.signature.XMLSignature;
import org.codelibs.saml4j.Reason;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;

/**
 * Signature verification and decryption on top of the XML security library.
 *
 * <p>The library is never handed a document that has not been through an allow-list first: every element in a
 * signature or an encrypted block must be one this class knows, and every algorithm URI must be one of the lists in
 * {@link Names}. What the library would otherwise log or fetch from an attacker-chosen value is therefore never
 * reached.</p>
 */
public final class XmlSecurity {

    static {
        org.apache.xml.security.Init.init();
    }

    private static final Set<String> SIGNATURE_ELEMENTS = Set.of("SignedInfo", "SignatureValue", "KeyInfo");

    private static final Set<String> ENC_ELEMENTS = Set.of("EncryptedData", "EncryptionMethod", "CipherData", "CipherValue", "EncryptedKey",
            "ReferenceList", "DataReference", "KeyReference", "OAEPparams", "CarriedKeyName");

    private static final Set<String> KEYINFO_ELEMENTS =
            Set.of("KeyInfo", "KeyName", "X509Data", "X509Certificate", "X509IssuerSerial", "X509IssuerName", "X509SerialNumber", "X509SKI",
                    "X509SubjectName", "DigestMethod", "RetrievalMethod", "KeyValue", "RSAKeyValue", "Modulus", "Exponent");

    private static final String XMLNS = "http://www.w3.org/2000/xmlns/";

    private static final String ENCRYPTED_KEY_TYPE = Names.NS_XENC + "EncryptedKey";

    private XmlSecurity() {
    }

    /**
     * Verifies the one signature that is a direct child of an element. On success the element is covered: its
     * digest was computed over the element itself, which the signature references by its own ID.
     *
     * @param signed the element that carries the signature
     * @param certs the certificates that may sign
     * @param allowDeprecated whether SHA-1 based algorithms are accepted
     * @return {@code false} if the element has no signature
     * @throws Refusal if a signature is present but not acceptable
     */
    public static boolean verifyEnveloped(final Element signed, final List<X509Certificate> certs, final boolean allowDeprecated) {
        final List<Element> sigs = SafeXml.children(signed, Names.NS_DS, "Signature");
        if (sigs.isEmpty()) {
            return false;
        }
        if (sigs.size() > 1) {
            throw new Refusal(Reason.INVALID_SIGNATURE, "more than one signature");
        }
        final String id = SafeXml.attr(signed, "ID");
        if (id == null || id.isEmpty()) {
            throw new Refusal(Reason.INVALID_SIGNATURE, "signed element has no ID");
        }
        final Element sig = sigs.get(0);
        checkSignature(sig, id, allowDeprecated);
        try {
            signed.setIdAttributeNS(null, "ID", true);
            final XMLSignature signature = new XMLSignature(sig, "", true);
            for (final X509Certificate cert : certs) {
                try {
                    if (signature.checkSignatureValue(cert)) {
                        return true;
                    }
                } catch (final org.apache.xml.security.exceptions.XMLSecurityException e) {
                    // this certificate does not verify the signature; try the next one
                    continue;
                }
            }
        } catch (final org.apache.xml.security.exceptions.XMLSecurityException e) {
            throw new Refusal(Reason.INVALID_SIGNATURE, "signature cannot be read");
        }
        throw new Refusal(Reason.INVALID_SIGNATURE, "signature does not verify");
    }

    private static void checkSignature(final Element sig, final String id, final boolean allowDeprecated) {
        for (final Element c : SafeXml.children(sig)) {
            if (!Names.NS_DS.equals(c.getNamespaceURI()) || !SIGNATURE_ELEMENTS.contains(c.getLocalName())) {
                throw new Refusal(Reason.INVALID_SIGNATURE, "unexpected element in signature");
            }
        }
        final Element info = SafeXml.requiredChild(sig, Names.NS_DS, "SignedInfo");
        SafeXml.requiredChild(sig, Names.NS_DS, "SignatureValue");
        SafeXml.optionalChild(sig, Names.NS_DS, "KeyInfo");
        int refs = 0;
        boolean c14n = false;
        boolean method = false;
        for (final Element c : SafeXml.children(info)) {
            if (!Names.NS_DS.equals(c.getNamespaceURI())) {
                throw new Refusal(Reason.INVALID_SIGNATURE, "unexpected element in SignedInfo");
            }
            switch (c.getLocalName()) {
            case "CanonicalizationMethod":
                requireAlgorithm(c, Names.C14N_METHODS, null, true);
                c14n = true;
                break;
            case "SignatureMethod":
                requireAlgorithm(c, Names.XML_SIGNATURE_METHODS, allowDeprecated ? Names.DEPRECATED_SIGNATURE_METHODS : null, false);
                method = true;
                break;
            case "Reference":
                refs++;
                checkReference(c, id, allowDeprecated);
                break;
            default:
                throw new Refusal(Reason.INVALID_SIGNATURE, "unexpected element in SignedInfo");
            }
        }
        if (refs != 1 || !c14n || !method) {
            throw new Refusal(Reason.INVALID_SIGNATURE, "SignedInfo is not the expected shape");
        }
    }

    private static void checkReference(final Element ref, final String id, final boolean allowDeprecated) {
        final String uri = SafeXml.attr(ref, "URI");
        if (uri == null || !uri.equals("#" + id)) {
            throw new Refusal(Reason.INVALID_SIGNATURE, "reference does not point at the signed element");
        }
        boolean digest = false;
        for (final Element c : SafeXml.children(ref)) {
            if (!Names.NS_DS.equals(c.getNamespaceURI())) {
                throw new Refusal(Reason.INVALID_SIGNATURE, "unexpected element in Reference");
            }
            switch (c.getLocalName()) {
            case "Transforms":
                final List<Element> transforms = SafeXml.children(c);
                if (transforms.isEmpty() || transforms.size() > 2) {
                    throw new Refusal(Reason.INVALID_SIGNATURE, "unexpected number of transforms");
                }
                for (final Element t : transforms) {
                    if (!SafeXml.is(t, Names.NS_DS, "Transform")) {
                        throw new Refusal(Reason.INVALID_SIGNATURE, "unexpected element in Transforms");
                    }
                    final String alg = t.getAttributeNS(null, "Algorithm");
                    if (!Names.ENVELOPED.equals(alg) && !Names.C14N_METHODS.contains(alg)) {
                        throw new Refusal(Reason.INVALID_SIGNATURE, "transform is not allowed: " + Text.safe(alg));
                    }
                    for (final Element tc : SafeXml.children(t)) {
                        if (!SafeXml.is(tc, Names.NS_EXC_C14N, "InclusiveNamespaces")) {
                            throw new Refusal(Reason.INVALID_SIGNATURE, "unexpected element in Transform");
                        }
                    }
                }
                break;
            case "DigestMethod":
                requireAlgorithm(c, Names.DIGEST_METHODS, allowDeprecated ? Names.DEPRECATED_DIGEST_METHODS : null, false);
                digest = true;
                break;
            case "DigestValue":
                break;
            default:
                throw new Refusal(Reason.INVALID_SIGNATURE, "unexpected element in Reference");
            }
        }
        if (!digest) {
            throw new Refusal(Reason.INVALID_SIGNATURE, "Reference has no DigestMethod");
        }
    }

    private static void requireAlgorithm(final Element e, final Set<String> allowed, final Set<String> extra, final boolean allowChildren) {
        final String alg = SafeXml.attr(e, "Algorithm");
        if (alg == null || !allowed.contains(alg) && (extra == null || !extra.contains(alg))) {
            throw new Refusal(Reason.INVALID_SIGNATURE, "algorithm is not allowed: " + Text.safe(alg));
        }
        for (final Element c : SafeXml.children(e)) {
            if (!allowChildren || !SafeXml.is(c, Names.NS_EXC_C14N, "InclusiveNamespaces")) {
                throw new Refusal(Reason.INVALID_SIGNATURE, "unexpected element in " + e.getLocalName());
            }
        }
    }

    /**
     * Decrypts the EncryptedData of an EncryptedAssertion or EncryptedID and parses the plaintext.
     *
     * @param container the {@code EncryptedAssertion} or {@code EncryptedID} element
     * @param key the private key of this service provider, or {@code null}
     * @param allowRsa15 whether RSA 1.5 key transport is accepted
     * @return the plaintext document
     * @throws Refusal if the block is not acceptable or cannot be decrypted
     */
    public static Element decrypt(final Element container, final PrivateKey key, final boolean allowRsa15) {
        if (key == null) {
            throw new Refusal(Reason.DECRYPTION_FAILED, "no private key is configured");
        }
        final Element data = SafeXml.requiredChild(container, Names.NS_XENC, "EncryptedData");
        final Element encKey = checkEncrypted(container, data, allowRsa15);
        final String dataAlg = SafeXml.attr(SafeXml.requiredChild(data, Names.NS_XENC, "EncryptionMethod"), "Algorithm");
        try {
            final XMLCipher keyCipher = XMLCipher.getInstance();
            keyCipher.init(XMLCipher.UNWRAP_MODE, key);
            final EncryptedKey ek = keyCipher.loadEncryptedKey(container.getOwnerDocument(), encKey);
            final Key symmetric = keyCipher.decryptKey(ek, dataAlg);
            final XMLCipher dataCipher = XMLCipher.getInstance();
            dataCipher.init(XMLCipher.DECRYPT_MODE, symmetric);
            final byte[] plain = dataCipher.decryptToByteArray(data);
            return parseInContext(plain, container);
        } catch (final Refusal e) {
            throw new Refusal(Reason.DECRYPTION_FAILED, "decryption failed");
        } catch (final Exception e) {
            throw new Refusal(Reason.DECRYPTION_FAILED, "decryption failed");
        }
    }

    /**
     * Parses a decrypted element where it came from: the plaintext of an encrypted element is serialized without
     * the namespace declarations of its ancestors, so it is read inside a wrapper that carries the declarations in
     * scope at the encrypted block, and the wrapper is dropped.
     */
    private static Element parseInContext(final byte[] plain, final Element container) {
        final Map<String, String> declarations = new LinkedHashMap<>();
        for (Node n = container; n != null && n.getNodeType() == Node.ELEMENT_NODE; n = n.getParentNode()) {
            final NamedNodeMap attrs = n.getAttributes();
            for (int i = 0; i < attrs.getLength(); i++) {
                final Node a = attrs.item(i);
                if (XMLNS.equals(a.getNamespaceURI())) {
                    declarations.putIfAbsent(a.getNodeName(), a.getNodeValue());
                }
            }
        }
        final StringBuilder sb = new StringBuilder("<w");
        declarations.forEach((name, value) -> sb.append(' ').append(name).append("=\"").append(Text.xml(value)).append('"'));
        sb.append('>');
        String text = new String(plain, StandardCharsets.UTF_8);
        if (!text.isEmpty() && text.charAt(0) == '\uFEFF') {
            text = text.substring(1);
        }
        sb.append(text.replaceFirst("^\\s*<\\?xml[^>]*\\?>", "")).append("</w>");
        final Document doc = SafeXml.parse(sb.toString().getBytes(StandardCharsets.UTF_8));
        final List<Element> children = SafeXml.children(doc.getDocumentElement());
        if (children.size() != 1) {
            throw new Refusal(Reason.DECRYPTION_FAILED, "the plaintext is not a single element");
        }
        for (Node c = doc.getDocumentElement().getFirstChild(); c != null; c = c.getNextSibling()) {
            if (c.getNodeType() == Node.TEXT_NODE && !c.getNodeValue().isBlank() || c.getNodeType() == Node.CDATA_SECTION_NODE) {
                throw new Refusal(Reason.DECRYPTION_FAILED, "the plaintext is not a single element");
            }
        }
        return children.get(0);
    }

    private static Element checkEncrypted(final Element container, final Element data, final boolean allowRsa15) {
        Element encKey = null;
        int keys = 0;
        int datas = 0;
        final Deque<Element> stack = new ArrayDeque<>(SafeXml.children(container));
        while (!stack.isEmpty()) {
            final Element e = stack.pop();
            final String ns = e.getNamespaceURI();
            final String name = e.getLocalName();
            if (Names.NS_XENC.equals(ns) && ENC_ELEMENTS.contains(name)) {
                if ("EncryptedKey".equals(name)) {
                    keys++;
                    encKey = e;
                } else if ("EncryptedData".equals(name)) {
                    datas++;
                } else if ("EncryptionMethod".equals(name)) {
                    final boolean forKey = e.getParentNode() instanceof Element p && SafeXml.is(p, Names.NS_XENC, "EncryptedKey");
                    checkEncryptionMethod(e, forKey, allowRsa15);
                }
            } else if (Names.NS_XENC11.equals(ns) && "MGF".equals(name)) {
                final String alg = SafeXml.attr(e, "Algorithm");
                if (alg == null || !Names.MGF.contains(alg)) {
                    throw new Refusal(Reason.DECRYPTION_FAILED, "mask generation function is not allowed: " + Text.safe(alg));
                }
            } else if (Names.NS_DS.equals(ns) && KEYINFO_ELEMENTS.contains(name)) {
                if ("DigestMethod".equals(name)) {
                    final String alg = SafeXml.attr(e, "Algorithm");
                    if (alg == null || !Names.DIGEST_METHODS.contains(alg) && !Names.DEPRECATED_DIGEST_METHODS.contains(alg)) {
                        throw new Refusal(Reason.DECRYPTION_FAILED, "digest is not allowed: " + Text.safe(alg));
                    }
                }
            } else {
                throw new Refusal(Reason.DECRYPTION_FAILED, "unexpected element in encrypted block");
            }
            stack.addAll(SafeXml.children(e));
        }
        if (keys != 1 || datas != 1 || encKey == null) {
            throw new Refusal(Reason.DECRYPTION_FAILED, "expected exactly one EncryptedData and one EncryptedKey");
        }
        for (final Element r : SafeXml.children(data, Names.NS_DS, "KeyInfo")) {
            for (final Element m : SafeXml.children(r, Names.NS_DS, "RetrievalMethod")) {
                final String type = SafeXml.attr(m, "Type");
                final String id = SafeXml.attr(encKey, "Id");
                if (id == null || !("#" + id).equals(SafeXml.attr(m, "URI")) || type != null && !ENCRYPTED_KEY_TYPE.equals(type)) {
                    throw new Refusal(Reason.DECRYPTION_FAILED, "RetrievalMethod does not point at the EncryptedKey");
                }
            }
        }
        return encKey;
    }

    private static void checkEncryptionMethod(final Element method, final boolean forKey, final boolean allowRsa15) {
        final String alg = SafeXml.attr(method, "Algorithm");
        final boolean ok;
        if (forKey) {
            ok = alg != null && (Names.KEY_TRANSPORT_OAEP.contains(alg) || allowRsa15 && Names.KEY_TRANSPORT_RSA15.equals(alg));
        } else {
            ok = alg != null && Names.DATA_ENCRYPTION.contains(alg);
        }
        if (!ok) {
            throw new Refusal(Reason.DECRYPTION_FAILED, "encryption algorithm is not allowed: " + Text.safe(alg));
        }
    }
}
