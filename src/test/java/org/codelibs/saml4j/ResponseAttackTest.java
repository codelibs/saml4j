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

import static org.codelibs.saml4j.ResponseTestSupport.PENDING;
import static org.codelibs.saml4j.ResponseTestSupport.accepted;
import static org.codelibs.saml4j.ResponseTestSupport.assertion;
import static org.codelibs.saml4j.ResponseTestSupport.child;
import static org.codelibs.saml4j.ResponseTestSupport.configWithKey;
import static org.codelibs.saml4j.ResponseTestSupport.controlAndChange;
import static org.codelibs.saml4j.ResponseTestSupport.element;
import static org.codelibs.saml4j.ResponseTestSupport.first;
import static org.codelibs.saml4j.ResponseTestSupport.forgedAssertion;
import static org.codelibs.saml4j.ResponseTestSupport.login;
import static org.codelibs.saml4j.ResponseTestSupport.refused;
import static org.codelibs.saml4j.ResponseTestSupport.response;
import static org.codelibs.saml4j.ResponseTestSupport.signAssertion;
import static org.codelibs.saml4j.ResponseTestSupport.signResponse;
import static org.codelibs.saml4j.ResponseTestSupport.signatureOf;
import static org.codelibs.saml4j.ResponseTestSupport.signedResponse;
import static org.codelibs.saml4j.ResponseTestSupport.unsigned;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.logging.Level;

import org.codelibs.saml4j.ResponseTestSupport.Canary;
import org.codelibs.saml4j.ResponseTestSupport.LogCapture;
import org.codelibs.saml4j.internal.Names;
import org.codelibs.saml4j.internal.SafeXml;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Hostile input to {@link ServiceProvider#finishLogin}: restructured and re-signed documents, hostile XML, hostile
 * encrypted blocks and hostile algorithm identifiers. Every refusal is checked against the response without the
 * change, which is accepted.
 */
public class ResponseAttackTest {

    private static final String MARKER = "FORGED-LOG-ENTRY";

    private static final String[] LINE_BREAKS = { "\n", "\r\n", " ", "\u0085" };

    private static final String XENC11_RSA_OAEP = "http://www.w3.org/2009/xmlenc11#rsa-oaep";

    // ---- helpers ---------------------------------------------------------------------------------------------------

    private static Document draft() {
        return unsigned(TestIdp.response());
    }

    /** A document whose assertion alone is signed. */
    private static Document assertionSigned() {
        final TestIdp.ResponseSpec spec = TestIdp.response();
        spec.signResponse = false;
        spec.signAssertion = true;
        return spec.document();
    }

    private static Element extensions(final Document doc) {
        final Element ext = element(doc, Names.NS_SAMLP, "samlp:Extensions");
        response(doc).appendChild(ext);
        return ext;
    }

    private static void assertDetailHas(final LoginResult.Rejected r, final String fragment) {
        assertTrue(r.detail().contains(fragment), "detail was: " + r.detail());
    }

    private static void assertDetailIsOneLine(final LoginResult.Rejected r) {
        assertTrue(
                r.detail()
                        .chars()
                        .noneMatch(c -> c == '\n' || c == '\r' || c == 0x2028 || c == 0x2029 || c == 0x85 || Character.isISOControl(c)),
                "detail has a control character: " + r.detail());
    }

    /** Fails when the message does not carry the marker in an attribute right behind a line break after parsing. */
    private static void assertLineBreakSurvives(final String encodedMessage) {
        final Document doc = TestIdp.parse(new String(Base64.getDecoder().decode(encodedMessage), StandardCharsets.UTF_8));
        final org.w3c.dom.NodeList all = doc.getElementsByTagName("*");
        for (int i = 0; i < all.getLength(); i++) {
            final org.w3c.dom.NamedNodeMap attributes = all.item(i).getAttributes();
            for (int j = 0; j < attributes.getLength(); j++) {
                final String value = attributes.item(j).getNodeValue();
                final int at = value.indexOf(MARKER);
                if (at > 0 && "\n\r\u2028\u0085".indexOf(value.charAt(at - 1)) >= 0) {
                    return;
                }
            }
        }
        throw new AssertionError("the line break did not survive serialization");
    }

    /**
     * Accepts the control, then refuses the changed message with the reason while a logger is attached around that one
     * call only (building the messages logs too), and checks that nothing of the marker reached it.
     */
    private static LoginResult.Rejected refusedQuietly(final SamlConfig.Builder config, final Reason reason, final String control,
            final String attack) {
        accepted(login(config, control));
        assertLineBreakSurvives(attack);
        try (LogCapture log = new LogCapture()) {
            final LoginResult.Rejected r = refused(reason, login(config, attack));
            assertDetailIsOneLine(r);
            assertFalse(log.text(Level.ALL).contains(MARKER), "logged: " + log.text(Level.ALL));
            return r;
        }
    }

    /** Builds a signed response from a document that is changed before signing when {@code attack} is set. */
    private static Function<Boolean, String> signedAfter(final Consumer<Document> change) {
        return attack -> {
            final Document doc = draft();
            if (attack) {
                change.accept(doc);
            }
            return signedResponse(doc);
        };
    }

    /** Builds a response that is signed first and changed afterwards when {@code attack} is set. */
    private static Function<Boolean, String> signedBefore(final Consumer<Document> change) {
        return attack -> {
            final Document doc = TestIdp.response().document();
            if (attack) {
                change.accept(doc);
            }
            return TestIdp.encode(doc);
        };
    }

    // ---- signature wrapping ----------------------------------------------------------------------------------------

    @Test
    public void testSignedAssertionMovedIntoExtensionsNextToAnUnsignedOneIsRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = assertionSigned();
            if (attack) {
                final Element signed = assertion(doc);
                response(doc).removeChild(signed);
                extensions(doc).appendChild(signed);
                response(doc).appendChild(forgedAssertion(doc, "admin@example.com"));
            }
            return TestIdp.encode(doc);
        });
        assertDetailHas(r, "exactly one assertion");
    }

    @Test
    public void testSignedAssertionMovedIntoAdviceOfAnUnsignedOneIsRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = assertionSigned();
            if (attack) {
                final Element signed = assertion(doc);
                final Element forged = forgedAssertion(doc, "admin@example.com");
                response(doc).replaceChild(forged, signed);
                final Element advice = element(doc, Names.NS_SAML, "saml:Advice");
                advice.appendChild(signed);
                forged.appendChild(advice);
            }
            return TestIdp.encode(doc);
        });
        assertDetailHas(r, "exactly one assertion");
    }

    @Test
    public void testUnsignedAssertionInsideTheAdviceOfASignedOneIsRefused() {
        controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = draft();
            if (attack) {
                final Element advice = element(doc, Names.NS_SAML, "saml:Advice");
                advice.appendChild(forgedAssertion(doc, "admin@example.com"));
                assertion(doc).appendChild(advice);
            }
            signAssertion(doc);
            return signedResponse(doc);
        });
    }

    @Test
    public void testSignedAssertionOnlyInsideExtensionsIsRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = assertionSigned();
            if (attack) {
                final Element signed = assertion(doc);
                response(doc).removeChild(signed);
                extensions(doc).appendChild(signed);
            }
            return TestIdp.encode(doc);
        });
        assertDetailHas(r, "not a child of the Response");
    }

    @Test
    public void testForgedAssertionWithTheIdOfTheSignedOneIsRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = assertionSigned();
            if (attack) {
                final Element signed = assertion(doc);
                final String id = signed.getAttribute("ID");
                response(doc).removeChild(signed);
                extensions(doc).appendChild(signed);
                final Element forged = forgedAssertion(doc, "admin@example.com");
                forged.setAttribute("ID", id);
                response(doc).appendChild(forged);
            }
            return TestIdp.encode(doc);
        });
        assertDetailHas(r, "duplicate ID");
    }

    @Test
    public void testForgedAssertionCarryingTheSignatureOfAnotherIsRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE, attack -> {
            final Document doc = assertionSigned();
            if (attack) {
                final Element signed = assertion(doc);
                final Element forged = forgedAssertion(doc, "admin@example.com");
                forged.insertBefore(signatureOf(signed).cloneNode(true), forged.getFirstChild().getNextSibling());
                response(doc).replaceChild(forged, signed);
            }
            return TestIdp.encode(doc);
        });
        assertDetailHas(r, "reference does not point");
    }

    @Test
    public void testForgedAssertionWithTheSignedIdAndTheCopiedSignatureIsRefused() {
        controlAndChange(Reason.INVALID_SIGNATURE, attack -> {
            final Document doc = assertionSigned();
            if (attack) {
                final Element signed = assertion(doc);
                final Element forged = forgedAssertion(doc, "admin@example.com");
                forged.setAttribute("ID", signed.getAttribute("ID"));
                forged.insertBefore(signatureOf(signed).cloneNode(true), forged.getFirstChild().getNextSibling());
                response(doc).replaceChild(forged, signed);
            }
            return TestIdp.encode(doc);
        });
    }

    @Test
    public void testSignedResponseNestedInsideAnUnsignedResponseIsRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.MALFORMED, attack -> {
            final Document inner = TestIdp.response().document();
            if (!attack) {
                return TestIdp.encode(inner);
            }
            final TestIdp.ResponseSpec spec = TestIdp.response();
            spec.nameId = "admin@example.com";
            final Document outer = unsigned(spec);
            extensions(outer).appendChild(outer.importNode(response(inner), true));
            return TestIdp.encode(outer);
        });
        assertDetailHas(r, "exactly one assertion");
    }

    @Test
    public void testSignedResponseWithoutAssertionInsideAnUnsignedResponseIsRefused() {
        controlAndChange(Reason.NOT_SIGNED, attack -> {
            if (!attack) {
                return TestIdp.response().encoded();
            }
            final Document inner = draft();
            response(inner).removeChild(assertion(inner));
            signResponse(inner);
            final TestIdp.ResponseSpec spec = TestIdp.response();
            spec.nameId = "admin@example.com";
            final Document outer = unsigned(spec);
            extensions(outer).appendChild(outer.importNode(response(inner), true));
            return TestIdp.encode(outer);
        });
    }

    @Test
    public void testSignatureMovedIntoExtensionsDoesNotSignTheResponse() {
        controlAndChange(Reason.NOT_SIGNED, signedBefore(doc -> {
            final Element sig = signatureOf(response(doc));
            response(doc).removeChild(sig);
            extensions(doc).appendChild(sig);
        }));
    }

    @Test
    public void testSignatureOfTheAssertionMovedOntoTheResponseIsRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE, attack -> {
            final Document doc = assertionSigned();
            if (attack) {
                final Element sig = signatureOf(assertion(doc));
                assertion(doc).removeChild(sig);
                response(doc).insertBefore(sig, assertion(doc));
            }
            return TestIdp.encode(doc);
        });
        assertDetailHas(r, "reference does not point");
    }

    @Test
    public void testSecondSignatureOnTheResponseIsRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE, signedBefore(doc -> {
            final Element sig = signatureOf(response(doc));
            response(doc).insertBefore(sig.cloneNode(true), sig);
        }));
        assertDetailHas(r, "more than one signature");
    }

    @Test
    public void testSecondSignatureOnTheAssertionIsRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE, attack -> {
            final Document doc = assertionSigned();
            if (attack) {
                final Element sig = signatureOf(assertion(doc));
                assertion(doc).insertBefore(sig.cloneNode(true), sig);
            }
            return TestIdp.encode(doc);
        });
        assertDetailHas(r, "more than one signature");
    }

    @Test
    public void testSignatureByAnotherKeyWithItsCertificateInKeyInfoIsRefused() {
        controlAndChange(Reason.INVALID_SIGNATURE, attack -> {
            final TestIdp.ResponseSpec spec = TestIdp.response();
            spec.signKey = attack ? TestIdp.OTHER_KEY : TestIdp.IDP_KEY;
            final Document doc = spec.document();
            if (attack) {
                final Element keyInfo = element(doc, Names.NS_DS, "ds:KeyInfo");
                final Element data = element(doc, Names.NS_DS, "ds:X509Data");
                final Element cert = element(doc, Names.NS_DS, "ds:X509Certificate");
                cert.setTextContent(Base64.getEncoder().encodeToString(encoded(TestIdp.OTHER_CERT)));
                data.appendChild(cert);
                keyInfo.appendChild(data);
                signatureOf(response(doc)).appendChild(keyInfo);
            }
            return TestIdp.encode(doc);
        });
    }

    private static byte[] encoded(final java.security.cert.X509Certificate cert) {
        try {
            return cert.getEncoded();
        } catch (final java.security.cert.CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    @Test
    public void testKeyInfoWithARetrievalMethodIsNotFollowed() {
        try (Canary canary = new Canary()) {
            final Document doc = TestIdp.response().document();
            final Element keyInfo = element(doc, Names.NS_DS, "ds:KeyInfo");
            final Element retrieval = element(doc, Names.NS_DS, "ds:RetrievalMethod");
            retrieval.setAttribute("URI", canary.url("/key"));
            keyInfo.appendChild(retrieval);
            signatureOf(response(doc)).appendChild(keyInfo);
            accepted(login(TestIdp.encode(doc)));
            assertEquals(0, canary.hits());
        }
    }

    // ---- what the signature refers to ------------------------------------------------------------------------------

    @Test
    public void testReferenceThatDoesNotPointAtTheSignedElementIsRefused() {
        for (final String uri : new String[] { "", "#", "#_other", "#_other_" + System.nanoTime(), "http://127.0.0.1/doc#x" }) {
            final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE,
                    signedBefore(doc -> first(doc, Names.NS_DS, "Reference").setAttribute("URI", uri)));
            assertDetailHas(r, "reference does not point");
        }
    }

    @Test
    public void testReferenceWithoutUriIsRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE,
                signedBefore(doc -> first(doc, Names.NS_DS, "Reference").removeAttribute("URI")));
        assertDetailHas(r, "reference does not point");
    }

    @Test
    public void testReferenceToTheAssertionFromASignatureOnTheResponseIsRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE, signedBefore(doc -> {
            first(doc, Names.NS_DS, "Reference").setAttribute("URI", "#" + assertion(doc).getAttribute("ID"));
        }));
        assertDetailHas(r, "reference does not point");
    }

    @Test
    public void testSecondReferenceIsRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE, signedBefore(doc -> {
            final Element ref = first(doc, Names.NS_DS, "Reference");
            ref.getParentNode().appendChild(ref.cloneNode(true));
        }));
        assertDetailHas(r, "not the expected shape");
    }

    @Test
    public void testTransformOutsideTheAllowListIsRefused() {
        for (final String alg : new String[] { "http://www.w3.org/TR/1999/REC-xpath-19991116",
                "http://www.w3.org/TR/1999/REC-xslt-19991116", "http://www.w3.org/2002/06/xmldsig-filter2",
                "http://www.w3.org/2000/09/xmldsig#base64", "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments", "urn:example:transform", "" }) {
            final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE,
                    signedBefore(doc -> first(doc, Names.NS_DS, "Transform").setAttribute("Algorithm", alg)));
            assertDetailHas(r, "transform is not allowed");
        }
    }

    @Test
    public void testThirdTransformIsRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE, signedBefore(doc -> {
            final Element transform = first(doc, Names.NS_DS, "Transform");
            final Element extra = (Element) transform.cloneNode(true);
            transform.getParentNode().appendChild(extra);
        }));
        assertDetailHas(r, "number of transforms");
    }

    @Test
    public void testTransformWithAnXPathChildIsRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE, signedBefore(doc -> {
            final Element transform = first(doc, Names.NS_DS, "Transform");
            final Element xpath = element(doc, Names.NS_DS, "ds:XPath");
            xpath.setTextContent("not(ancestor-or-self::saml:Assertion)");
            transform.appendChild(xpath);
        }));
        assertDetailHas(r, "unexpected element in Transform");
    }

    @Test
    public void testUnexpectedElementInReferenceIsRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE, signedBefore(doc -> {
            final Element ref = first(doc, Names.NS_DS, "Reference");
            ref.appendChild(element(doc, Names.NS_DS, "ds:Manifest"));
        }));
        assertDetailHas(r, "unexpected element in Reference");
    }

    @Test
    public void testHmacSignatureMethodIsRefused() {
        for (final String alg : new String[] { "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256",
                "http://www.w3.org/2000/09/xmldsig#hmac-sha1", "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512" }) {
            final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE,
                    signedBefore(doc -> first(doc, Names.NS_DS, "SignatureMethod").setAttribute("Algorithm", alg)));
            assertDetailHas(r, "algorithm is not allowed");
        }
    }

    @Test
    public void testOtherWeakOrUnknownSignatureMethodsAreRefused() {
        for (final String alg : new String[] { "http://www.w3.org/2001/04/xmldsig-more#rsa-md5",
                "http://www.w3.org/2000/09/xmldsig#dsa-sha1", "http://www.w3.org/2009/xmldsig11#dsa-sha256",
                "http://www.w3.org/2007/05/xmldsig-more#sha1-rsa-MGF1", "none", "" }) {
            final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE,
                    signedBefore(doc -> first(doc, Names.NS_DS, "SignatureMethod").setAttribute("Algorithm", alg)));
            assertDetailHas(r, "algorithm is not allowed");
        }
    }

    @Test
    public void testSignatureMadeWithRsaMd5IsRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE,
                attack -> encodedWith(attack ? "http://www.w3.org/2001/04/xmldsig-more#rsa-md5" : Names.RSA_SHA256,
                        ResponseTestSupport.SHA256));
        assertDetailHas(r, "algorithm is not allowed");
    }

    @Test
    public void testDigestMethodsOutsideTheAllowListAreRefused() {
        for (final String alg : new String[] { "http://www.w3.org/2001/04/xmldsig-more#md5", "http://www.w3.org/2001/04/xmlenc#ripemd160",
                "http://www.w3.org/2001/04/xmldsig-more#sha224", "urn:example:digest", "" }) {
            final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE,
                    signedBefore(doc -> first(doc, Names.NS_DS, "DigestMethod").setAttribute("Algorithm", alg)));
            assertDetailHas(r, "algorithm is not allowed");
        }
    }

    @Test
    public void testCanonicalizationWithCommentsIsRefused() {
        for (final String alg : new String[] { "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
                "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments", "http://www.w3.org/2006/12/xml-c14n11#WithComments" }) {
            final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE,
                    signedBefore(doc -> first(doc, Names.NS_DS, "CanonicalizationMethod").setAttribute("Algorithm", alg)));
            assertDetailHas(r, "algorithm is not allowed");
        }
    }

    private static String encodedWith(final String sigAlg, final String digestAlg) {
        final TestIdp.ResponseSpec spec = TestIdp.response();
        spec.sigAlg = sigAlg;
        spec.digestAlg = digestAlg;
        return spec.encoded();
    }

    @Test
    public void testObjectInsideTheSignatureIsRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE, signedBefore(doc -> {
            final Element object = element(doc, Names.NS_DS, "ds:Object");
            object.setAttribute("Id", "payload");
            signatureOf(response(doc)).appendChild(object);
        }));
        assertDetailHas(r, "unexpected element in signature");
    }

    @Test
    public void testUnexpectedElementInSignedInfoIsRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.INVALID_SIGNATURE, signedBefore(doc -> {
            final Element info = first(doc, Names.NS_DS, "SignedInfo");
            info.appendChild(element(doc, Names.NS_DS, "ds:Extra"));
        }));
        assertDetailHas(r, "unexpected element in SignedInfo");
    }

    @Test
    public void testSignatureWithoutSignedInfoIsRefusedWithoutAnException() {
        controlAndChange(Reason.MALFORMED, signedBefore(doc -> {
            final Element info = first(doc, Names.NS_DS, "SignedInfo");
            info.getParentNode().removeChild(info);
        }));
    }

    // ---- duplicate IDs ---------------------------------------------------------------------------------------------

    @Test
    public void testAssertionWithTheIdOfTheResponseIsRefused() {
        // the signing library refuses to sign such a document, so the ID is changed afterwards
        final LoginResult.Rejected r = controlAndChange(Reason.MALFORMED,
                signedBefore(doc -> assertion(doc).setAttribute("ID", response(doc).getAttribute("ID"))));
        assertDetailHas(r, "duplicate ID");
    }

    @Test
    public void testSecondElementWithTheIdOfTheSignedResponseIsRefused() {
        for (final String attribute : new String[] { "ID", "Id", "id" }) {
            controlAndChange(Reason.MALFORMED, attack -> {
                final Document doc = draft();
                if (attack) {
                    first(doc, Names.NS_SAML, "Issuer").setAttribute(attribute, response(doc).getAttribute("ID"));
                }
                return signedResponse(doc);
            });
        }
    }

    @Test
    public void testSecondElementWithTheIdOfTheAssertionInsideTheSignatureIsRefused() {
        controlAndChange(Reason.MALFORMED,
                signedBefore(doc -> first(doc, Names.NS_DS, "SignatureValue").setAttribute("Id", assertion(doc).getAttribute("ID"))));
    }

    // ---- XML -------------------------------------------------------------------------------------------------------

    private static String signedXml() {
        return TestIdp.serialize(TestIdp.response().document());
    }

    private static String withDoctype(final String doctype, final String xml) {
        return doctype + xml;
    }

    @Test
    public void testDoctypeWithAnInternalEntityIsRefused() {
        final String xml = signedXml();
        accepted(login(TestIdp.encode(xml)));
        final LoginResult.Rejected r =
                refused(Reason.MALFORMED, login(TestIdp.encode(withDoctype("<!DOCTYPE samlp:Response [<!ENTITY e \"x\">]>", xml))));
        assertDetailIsOneLine(r);
    }

    @Test
    public void testExternalEntityIsRefusedAndNotRead() throws Exception {
        final Path secret = Files.createTempFile("saml4j-secret", ".txt");
        try (Canary canary = new Canary()) {
            Files.writeString(secret, "SECRET-CONTENT");
            final String xml = signedXml();
            accepted(login(TestIdp.encode(xml)));
            for (final String location : new String[] { secret.toUri().toString(), canary.url("/entity") }) {
                final String doctype = "<!DOCTYPE samlp:Response [<!ENTITY xxe SYSTEM \"" + location + "\">]>";
                refused(Reason.MALFORMED, login(TestIdp.encode(withDoctype(doctype, xml))));
                final String used = withDoctype(doctype, xml).replace("alice@example.com", "&xxe;");
                final LoginResult.Rejected r = refused(Reason.MALFORMED, login(TestIdp.encode(used)));
                assertFalse(r.detail().contains("SECRET-CONTENT"));
            }
            assertEquals(0, canary.hits());
        } finally {
            Files.deleteIfExists(secret);
        }
    }

    @Test
    public void testExternalDtdAndParameterEntityAreRefusedAndNotFetched() {
        try (Canary canary = new Canary()) {
            final String xml = signedXml();
            accepted(login(TestIdp.encode(xml)));
            refused(Reason.MALFORMED,
                    login(TestIdp.encode(withDoctype("<!DOCTYPE samlp:Response SYSTEM \"" + canary.url("/evil.dtd") + "\">", xml))));
            refused(Reason.MALFORMED, login(TestIdp
                    .encode(withDoctype("<!DOCTYPE samlp:Response [<!ENTITY % p SYSTEM \"" + canary.url("/p.dtd") + "\"> %p;]>", xml))));
            refused(Reason.MALFORMED, login(
                    TestIdp.encode(withDoctype("<!DOCTYPE samlp:Response PUBLIC \"-//x//EN\" \"" + canary.url("/pub.dtd") + "\">", xml))));
            assertEquals(0, canary.hits());
        }
    }

    @Test
    public void testNestedEntityDefinitionsAreRefused() {
        final StringBuilder dtd = new StringBuilder("<!DOCTYPE samlp:Response [<!ENTITY a0 \"lol\">");
        for (int i = 1; i < 10; i++) {
            dtd.append("<!ENTITY a").append(i).append(" \"");
            for (int j = 0; j < 10; j++) {
                dtd.append("&a").append(i - 1).append(';');
            }
            dtd.append("\">");
        }
        dtd.append("]>");
        final String xml = signedXml();
        accepted(login(TestIdp.encode(xml)));
        final String bomb = withDoctype(dtd.toString(), xml).replace("alice@example.com", "&a9;");
        refused(Reason.MALFORMED, login(TestIdp.encode(bomb)));
    }

    @Test
    public void testXIncludeInTheNameIdIsNotExpanded() throws Exception {
        final Path secret = Files.createTempFile("saml4j-secret", ".txt");
        try (Canary canary = new Canary()) {
            Files.writeString(secret, "SECRET-CONTENT");
            for (final String href : new String[] { secret.toUri().toString(), canary.url("/include") }) {
                final LoginResult.Rejected r = controlAndChange(Reason.MALFORMED, attack -> {
                    final Document doc = draft();
                    if (attack) {
                        final Element id = first(doc, Names.NS_SAML, "NameID");
                        id.setTextContent("");
                        final Element include = element(doc, "http://www.w3.org/2001/XInclude", "xi:include");
                        include.setAttribute("href", href);
                        include.setAttribute("parse", "text");
                        id.appendChild(include);
                    }
                    return signedResponse(doc);
                });
                assertFalse(r.detail().contains("SECRET-CONTENT"));
            }
            assertEquals(0, canary.hits());
        } finally {
            Files.deleteIfExists(secret);
        }
    }

    @Test
    public void testXIncludeInAnAttributeValueIsNotExpanded() throws Exception {
        final Path secret = Files.createTempFile("saml4j-secret", ".txt");
        try {
            Files.writeString(secret, "SECRET-CONTENT");
            final Document doc = draft();
            ResponseTestSupport.addAttribute(doc, "note", "");
            final List<Element> values = TestIdp.all(doc, Names.NS_SAML, "AttributeValue");
            final Element include = element(doc, "http://www.w3.org/2001/XInclude", "xi:include");
            include.setAttribute("href", secret.toUri().toString());
            include.setAttribute("parse", "text");
            values.get(values.size() - 1).appendChild(include);
            final LoginResult.Authenticated a = accepted(login(signedResponse(doc)));
            assertFalse(a.toString().contains("SECRET-CONTENT"), a.toString());
            assertEquals(List.of(), a.attributes().get("note"));
        } finally {
            Files.deleteIfExists(secret);
        }
    }

    // ---- size and shape --------------------------------------------------------------------------------------------

    private static String nested(final int levels) {
        return "<a>".repeat(levels) + "</a>".repeat(levels);
    }

    private static String signedWithNesting(final int levels) {
        final Document doc = draft();
        final Element ext = extensions(doc);
        Element parent = ext;
        for (int i = 0; i < levels; i++) {
            final Element e = doc.createElementNS(null, "a");
            parent.appendChild(e);
            parent = e;
        }
        return signedResponse(doc);
    }

    @Test
    public void testNestingJustInsideTheLimitIsAcceptedAndJustOutsideIsRefused() {
        // Response (1) / Extensions (2) / a ... : the deepest element is at depth 2 + levels
        controlAndChange(Reason.MALFORMED, attack -> signedWithNesting(SafeXml.MAX_DEPTH - (attack ? 1 : 2)));
    }

    @Test
    public void testNestingOf100LevelsIsRefused() {
        controlAndChange(Reason.MALFORMED, attack -> signedWithNesting(attack ? 100 : 10));
    }

    @Test
    public void testNestingOf20000LevelsIsRefused() {
        final String xml = signedXml();
        accepted(login(TestIdp.encode(xml)));
        final String deep = xml.replace("</samlp:Response>", "<samlp:Extensions>" + nested(20000) + "</samlp:Extensions></samlp:Response>");
        refused(Reason.TOO_LARGE, login(TestIdp.encode(deep)));
    }

    @Test
    public void testNestingOf20000LevelsThatIsNeverClosedIsRefused() {
        accepted(login(TestIdp.response().encoded()));
        refused(Reason.MALFORMED, login(TestIdp.encode("<a>".repeat(20000))));
    }

    @Test
    public void testNestingOf20000LevelsAsTheRootIsRefused() {
        accepted(login(TestIdp.response().encoded()));
        refused(Reason.TOO_LARGE, login(TestIdp.encode(nested(20000))));
    }

    @Test
    public void testElementCountAtTheLimitIsAcceptedAndOneMoreIsRefused() {
        final int base = elementCount(signedWithChildren(0));
        // base already holds the empty Extensions element
        final int room = SafeXml.MAX_ELEMENTS - base;
        controlAndChange(Reason.TOO_LARGE, attack -> TestIdp.encode(signedDocWithChildren(room + (attack ? 1 : 0))));
    }

    @Test
    public void testHugeElementCountIsRefused() {
        controlAndChange(Reason.TOO_LARGE, attack -> TestIdp.encode(signedDocWithChildren(attack ? 200_000 : 10)));
    }

    private static Document signedDocWithChildren(final int n) {
        final Document doc = draft();
        final Element ext = extensions(doc);
        for (int i = 0; i < n; i++) {
            ext.appendChild(doc.createElementNS(null, "e"));
        }
        signResponse(doc);
        return doc;
    }

    private static Document signedWithChildren(final int n) {
        return signedDocWithChildren(n);
    }

    private static int elementCount(final Document doc) {
        return doc.getElementsByTagName("*").getLength();
    }

    @Test
    public void testManyAttributesOnOneElementAreRefused() {
        final LoginResult.Rejected r = controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = draft();
            final Element ext = extensions(doc);
            for (int i = 0; i < (attack ? 200 : 10); i++) {
                ext.setAttribute("a" + i, "v");
            }
            return signedResponse(doc);
        });
        assertDetailIsOneLine(r);
    }

    @Test
    public void testMessageAtTheSizeLimitIsAcceptedAndOneByteMoreIsRefused() {
        final String xml = signedXml();
        final int size = xml.getBytes(StandardCharsets.UTF_8).length;
        final String message = TestIdp.encode(xml);
        accepted(login(TestIdp.config().maxMessageSize(size), message));
        refused(Reason.TOO_LARGE, login(TestIdp.config().maxMessageSize(size - 1), message));
    }

    @Test
    public void testHugeBase64TextIsRefused() {
        final String message = TestIdp.response().encoded();
        accepted(login(message));
        refused(Reason.TOO_LARGE, login("A".repeat(2_000_000)));
        refused(Reason.TOO_LARGE, login(" ".repeat(10_000_000)));
        refused(Reason.TOO_LARGE, login(message + "A".repeat(2_000_000)));
    }

    @Test
    public void testDecodedSizeBeyondTheLimitIsRefusedEvenWhenTheTextIsShortEnough() {
        final byte[] xml = signedXml().getBytes(StandardCharsets.UTF_8);
        final int limit = 1024 * 1024;
        final byte[] atLimit = java.util.Arrays.copyOf(xml, limit);
        java.util.Arrays.fill(atLimit, xml.length, limit, (byte) ' ');
        accepted(login(Base64.getEncoder().encodeToString(atLimit)));
        final byte[] over = java.util.Arrays.copyOf(atLimit, limit + 1);
        over[limit] = ' ';
        refused(Reason.TOO_LARGE, login(Base64.getEncoder().encodeToString(over)));
    }

    @Test
    public void testInputThatIsNotBase64IsRefused() {
        accepted(login(TestIdp.response().encoded()));
        for (final String text : new String[] { "!!!not base64!!!", "AAA", "A", "====", "PHNhbWw+<", "éééé", "-_-_-_-_" }) {
            refused(Reason.MALFORMED, login(text));
        }
    }

    @Test
    public void testEmptyAndMissingInputIsRefused() {
        accepted(login(TestIdp.response().encoded()));
        for (final String text : new String[] { null, "", "   ", "\r\n" }) {
            refused(Reason.MALFORMED, login(text));
        }
    }

    @Test
    public void testBase64WithLineBreaksIsAccepted() {
        final String message = TestIdp.response().encoded();
        final StringBuilder wrapped = new StringBuilder();
        for (int i = 0; i < message.length(); i += 76) {
            wrapped.append(message, i, Math.min(message.length(), i + 76)).append("\r\n");
        }
        accepted(login(wrapped.toString()));
    }

    @Test
    public void testInputThatIsNotXmlIsRefused() {
        accepted(login(TestIdp.response().encoded()));
        for (final String text : new String[] { "hello", "{\"a\":1}", "<samlp:Response", "<a></b>", "<?xml version=\"1.0\"?>",
                "\u0000\u0001\u0002", "<a/><b/>" }) {
            refused(Reason.MALFORMED, login(TestIdp.encode(text)));
        }
        refused(Reason.MALFORMED, login(Base64.getEncoder().encodeToString(new byte[] { (byte) 0xff, (byte) 0xfe, 0, 1, 2, (byte) 0x80 })));
        final String compressed = TestIdp.deflate(signedXml());
        refused(Reason.MALFORMED, login(compressed));
    }

    @Test
    public void testResponseInTheWrongNamespaceIsRefused() {
        controlAndChange(Reason.MALFORMED, attack -> {
            final String xml = signedXml();
            return TestIdp.encode(attack ? xml.replace(Names.NS_SAMLP, "urn:example:protocol") : xml);
        });
    }

    // ---- encrypted assertions --------------------------------------------------------------------------------------

    private static Element encryptedData(final Element enc) {
        return child(enc, Names.NS_XENC, "EncryptedData");
    }

    private static Element encryptedKey(final Element enc) {
        return (Element) enc.getElementsByTagNameNS(Names.NS_XENC, "EncryptedKey").item(0);
    }

    private static Element keyMethod(final Element enc) {
        return child(encryptedKey(enc), Names.NS_XENC, "EncryptionMethod");
    }

    private static Element dataMethod(final Element enc) {
        return child(encryptedData(enc), Names.NS_XENC, "EncryptionMethod");
    }

    private static Element dataKeyInfo(final Element enc) {
        return child(encryptedData(enc), Names.NS_DS, "KeyInfo");
    }

    private static Element dataCipherValue(final Element enc) {
        return child(child(encryptedData(enc), Names.NS_XENC, "CipherData"), Names.NS_XENC, "CipherValue");
    }

    private static String encryptedResponse(final String mode, final boolean attack, final Consumer<Element> change) {
        final Element enc = ResponseTestSupport.encrypt(ResponseTestSupport.plainAssertion(), mode).element("EncryptedAssertion");
        if (attack) {
            change.accept(enc);
        }
        return TestIdp.encode(ResponseTestSupport.responseWithEncryptedAssertion(enc, true));
    }

    /** The assertion is signed and then encrypted; the response carries no signature, so xmlsec sees nothing before the block is checked. */
    private static String encryptedInnerSigned(final boolean attack, final Consumer<Element> change) {
        final Document doc = draft();
        signAssertion(doc);
        final Element enc = ResponseTestSupport.encrypt(TestIdp.serialize(assertion(doc)), "cbc").element("EncryptedAssertion");
        if (attack) {
            change.accept(enc);
        }
        return TestIdp.encode(ResponseTestSupport.responseWithEncryptedAssertion(enc, false));
    }

    private static LoginResult.Rejected encryptedControlAndChange(final Reason reason, final Consumer<Element> change) {
        return controlAndChange(configWithKey(), reason, attack -> encryptedResponse("cbc", attack, change));
    }

    private static LoginResult.Rejected encryptedControlAndChange(final String mode, final Reason reason, final Consumer<Element> change) {
        return controlAndChange(configWithKey(), reason, attack -> encryptedResponse(mode, attack, change));
    }

    private static void useOaepWithMgf(final Element enc, final String mgfAlgorithm) {
        final Element method = keyMethod(enc);
        method.setAttribute("Algorithm", XENC11_RSA_OAEP);
        final Element mgf = element(enc.getOwnerDocument(), Names.NS_XENC11, "xenc11:MGF");
        mgf.setAttribute("Algorithm", mgfAlgorithm);
        method.appendChild(mgf);
    }

    private static byte[] decode(final Element value) {
        return Base64.getDecoder().decode(value.getTextContent().trim());
    }

    private static void encode(final Element value, final byte[] bytes) {
        value.setTextContent(Base64.getEncoder().encodeToString(bytes));
    }

    private static final String VALID_MGF = "http://www.w3.org/2009/xmlenc11#mgf1sha1";

    @Test
    public void testOaepWithMgfElementIsAcceptedWhenTheMgfIsOnTheList() {
        final String message = encryptedResponse("cbc", true, enc -> useOaepWithMgf(enc, VALID_MGF));
        accepted(login(configWithKey(), message));
    }

    @Test
    public void testMgfAlgorithmWithALineBreakIsRefusedAndNotLogged() {
        for (final String lineBreak : LINE_BREAKS) {
            final String control = encryptedInnerSigned(true, enc -> useOaepWithMgf(enc, VALID_MGF));
            final String attack = encryptedInnerSigned(true, enc -> useOaepWithMgf(enc, VALID_MGF + lineBreak + MARKER));
            final LoginResult.Rejected r = refusedQuietly(configWithKey(), Reason.DECRYPTION_FAILED, control, attack);
            assertDetailHas(r, "the encrypted assertion was not accepted");
        }
    }

    @Test
    public void testMgfAlgorithmOutsideTheListIsRefused() {
        for (final String algorithm : new String[] { "urn:example:mgf", "http://www.w3.org/2009/xmlenc11#mgf1md5", "" }) {
            final LoginResult.Rejected r = controlAndChange(configWithKey(), Reason.DECRYPTION_FAILED,
                    attack -> encryptedResponse("cbc", true, enc -> useOaepWithMgf(enc, attack ? algorithm : VALID_MGF)));
            assertDetailHas(r, "mask generation function is not allowed");
        }
    }

    @Test
    public void testMgfWithoutAlgorithmIsRefused() {
        controlAndChange(configWithKey(), Reason.DECRYPTION_FAILED, attack -> encryptedResponse("cbc", true, enc -> {
            useOaepWithMgf(enc, VALID_MGF);
            if (attack) {
                enc.getElementsByTagNameNS(Names.NS_XENC11, "MGF").item(0).getAttributes().removeNamedItem("Algorithm");
            }
        }));
    }

    @Test
    public void testEncryptionAlgorithmWithALineBreakIsRefusedAndNotLogged() {
        final List<Function<Element, Element>> places = List.of(ResponseAttackTest::keyMethod, ResponseAttackTest::dataMethod,
                enc -> (Element) keyMethod(enc).getElementsByTagNameNS(Names.NS_DS, "DigestMethod").item(0));
        for (final Function<Element, Element> place : places) {
            for (final String lineBreak : LINE_BREAKS) {
                final String control = encryptedInnerSigned(false, enc -> {});
                final String attack = encryptedInnerSigned(true, enc -> {
                    final Element e = place.apply(enc);
                    e.setAttribute("Algorithm", e.getAttribute("Algorithm") + lineBreak + MARKER);
                });
                refusedQuietly(configWithKey(), Reason.DECRYPTION_FAILED, control, attack);
            }
        }
    }

    @Test
    public void testSignatureAlgorithmWithALineBreakIsRefusedAndNotLogged() {
        for (final String local : new String[] { "SignatureMethod", "DigestMethod", "Transform", "CanonicalizationMethod" }) {
            for (final String lineBreak : LINE_BREAKS) {
                final Function<Boolean, String> build = signedBefore(doc -> {
                    final Element e = first(doc, Names.NS_DS, local);
                    e.setAttribute("Algorithm", e.getAttribute("Algorithm") + lineBreak + MARKER);
                });
                refusedQuietly(TestIdp.config(), Reason.INVALID_SIGNATURE, build.apply(false), build.apply(true));
            }
        }
    }

    @Test
    public void testSignatureAlgorithmWithALineBreakOnAnAssertionSignatureIsRefusedAndNotLogged() {
        for (final String lineBreak : LINE_BREAKS) {
            final Function<Boolean, String> build = attack -> {
                final Document doc = assertionSigned();
                if (attack) {
                    final Element e = first(doc, Names.NS_DS, "SignatureMethod");
                    e.setAttribute("Algorithm", e.getAttribute("Algorithm") + lineBreak + MARKER);
                }
                return TestIdp.encode(doc);
            };
            refusedQuietly(TestIdp.config(), Reason.INVALID_SIGNATURE, build.apply(false), build.apply(true));
        }
    }

    @Test
    public void testIdWithALineBreakIsRefusedBeforeAnySignatureWork() {
        for (final String lineBreak : LINE_BREAKS) {
            final Document doc = draft();
            response(doc).setAttribute("ID", "_r" + lineBreak + MARKER);
            signResponse(doc);
            final String message = TestIdp.encode(doc);
            assertLineBreakSurvives(message);
            try (LogCapture log = new LogCapture()) {
                final LoginResult.Rejected r = refused(Reason.MALFORMED, login(TestIdp.config(), message));
                assertDetailIsOneLine(r);
                assertFalse(log.text(Level.ALL).contains(MARKER), "logged: " + log.text(Level.ALL));
            }
        }
    }

    @Test
    public void testLogCaptureSeesWhatIsWrittenThroughTheLoggers() {
        try (LogCapture log = new LogCapture()) {
            java.util.logging.Logger.getLogger("probe.jul").fine("canary-jul");
            System.getLogger("probe.system").log(System.Logger.Level.DEBUG, "canary-system");
            assertTrue(log.text(Level.ALL).contains("canary-jul"));
            assertTrue(log.text(Level.ALL).contains("canary-system"));
        }
    }

    @Test
    public void testCipherReferenceIsRefusedAndNotFetched() {
        try (Canary canary = new Canary()) {
            final Consumer<Element> change = enc -> {
                final Element value = dataCipherValue(enc);
                final Element data = (Element) value.getParentNode();
                data.removeChild(value);
                final Element reference = element(enc.getOwnerDocument(), Names.NS_XENC, "xenc:CipherReference");
                reference.setAttribute("URI", canary.url("/cipher"));
                data.appendChild(reference);
            };
            final LoginResult.Rejected r = encryptedControlAndChange(Reason.DECRYPTION_FAILED, change);
            assertDetailHas(r, "unexpected element in encrypted block");
            assertEquals(0, canary.hits());
        }
    }

    @Test
    public void testCipherReferenceInsideTheEncryptedKeyIsRefusedAndNotFetched() {
        try (Canary canary = new Canary()) {
            encryptedControlAndChange(Reason.DECRYPTION_FAILED, enc -> {
                final Element value = (Element) encryptedKey(enc).getElementsByTagNameNS(Names.NS_XENC, "CipherValue").item(0);
                final Element data = (Element) value.getParentNode();
                data.removeChild(value);
                final Element reference = element(enc.getOwnerDocument(), Names.NS_XENC, "xenc:CipherReference");
                reference.setAttribute("URI", canary.url("/key"));
                data.appendChild(reference);
            });
            assertEquals(0, canary.hits());
        }
    }

    @Test
    public void testAgreementMethodIsRefused() {
        final LoginResult.Rejected r = encryptedControlAndChange(Reason.DECRYPTION_FAILED, enc -> {
            final Element agreement = element(enc.getOwnerDocument(), Names.NS_XENC, "xenc:AgreementMethod");
            agreement.setAttribute("Algorithm", "http://www.w3.org/2009/xmlenc11#ECDH-ES");
            dataKeyInfo(enc).appendChild(agreement);
        });
        assertDetailHas(r, "unexpected element in encrypted block");
    }

    @Test
    public void testDecoyEncryptedKeyBeforeTheRealOneIsRefused() {
        final LoginResult.Rejected r = encryptedControlAndChange(Reason.DECRYPTION_FAILED, enc -> {
            final Element real = encryptedKey(enc);
            final Element decoy = (Element) real.cloneNode(true);
            encode((Element) decoy.getElementsByTagNameNS(Names.NS_XENC, "CipherValue").item(0), new byte[256]);
            real.getParentNode().insertBefore(decoy, real);
        });
        assertDetailHas(r, "exactly one EncryptedData and one EncryptedKey");
    }

    @Test
    public void testDecoyEncryptedKeyAfterTheRealOneIsRefused() {
        encryptedControlAndChange(Reason.DECRYPTION_FAILED, enc -> {
            final Element real = encryptedKey(enc);
            final Element decoy = (Element) real.cloneNode(true);
            encode((Element) decoy.getElementsByTagNameNS(Names.NS_XENC, "CipherValue").item(0), new byte[256]);
            real.getParentNode().appendChild(decoy);
        });
    }

    @Test
    public void testEncryptedKeyOutsideTheEncryptedDataIsRefused() {
        encryptedControlAndChange(Reason.DECRYPTION_FAILED, enc -> enc.appendChild(encryptedKey(enc).cloneNode(true)));
    }

    @Test
    public void testSecondEncryptedDataIsRefused() {
        encryptedControlAndChange(Reason.MALFORMED, enc -> enc.appendChild(encryptedData(enc).cloneNode(true)));
    }

    @Test
    public void testEncryptedKeyWithoutEncryptedDataIsRefused() {
        encryptedControlAndChange(Reason.MALFORMED, enc -> enc.removeChild(encryptedData(enc)));
    }

    private static void addRetrievalMethod(final Element enc, final String uri, final String type) {
        encryptedKey(enc).setAttribute("Id", "_key1");
        final Element retrieval = element(enc.getOwnerDocument(), Names.NS_DS, "ds:RetrievalMethod");
        retrieval.setAttribute("URI", uri);
        if (type != null) {
            retrieval.setAttribute("Type", type);
        }
        dataKeyInfo(enc).appendChild(retrieval);
    }

    @Test
    public void testRetrievalMethodThatPointsAtTheEncryptedKeyIsAccepted() {
        accepted(login(configWithKey(),
                encryptedResponse("cbc", true, enc -> addRetrievalMethod(enc, "#_key1", Names.NS_XENC + "EncryptedKey"))));
    }

    @Test
    public void testRetrievalMethodThatPointsElsewhereIsRefusedAndNotFetched() {
        try (Canary canary = new Canary()) {
            for (final String uri : new String[] { "#_other", canary.url("/key"), "", "#" }) {
                final LoginResult.Rejected r =
                        controlAndChange(configWithKey(), Reason.DECRYPTION_FAILED, attack -> encryptedResponse("cbc", true,
                                enc -> addRetrievalMethod(enc, attack ? uri : "#_key1", Names.NS_XENC + "EncryptedKey")));
                assertDetailHas(r, "RetrievalMethod does not point at the EncryptedKey");
            }
            assertEquals(0, canary.hits());
        }
    }

    @Test
    public void testRetrievalMethodOfAnotherTypeIsRefused() {
        controlAndChange(configWithKey(), Reason.DECRYPTION_FAILED, attack -> encryptedResponse("cbc", true,
                enc -> addRetrievalMethod(enc, "#_key1", attack ? Names.NS_XENC + "EncryptedData" : Names.NS_XENC + "EncryptedKey")));
    }

    @Test
    public void testRetrievalMethodWhenTheEncryptedKeyHasNoIdIsRefused() {
        encryptedControlAndChange(Reason.DECRYPTION_FAILED, enc -> {
            final Element retrieval = element(enc.getOwnerDocument(), Names.NS_DS, "ds:RetrievalMethod");
            retrieval.setAttribute("URI", "#");
            dataKeyInfo(enc).appendChild(retrieval);
        });
    }

    @Test
    public void testDataEncryptionAlgorithmOutsideTheListIsRefused() {
        for (final String algorithm : new String[] { "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
                "http://www.w3.org/2001/04/xmlenc#kw-aes128", "http://www.w3.org/2001/04/xmlenc#des-cbc", "urn:example:cipher", "" }) {
            final LoginResult.Rejected r =
                    encryptedControlAndChange(Reason.DECRYPTION_FAILED, enc -> dataMethod(enc).setAttribute("Algorithm", algorithm));
            assertDetailHas(r, "encryption algorithm is not allowed");
        }
    }

    @Test
    public void testDataEncryptionMethodWithoutAlgorithmIsRefused() {
        encryptedControlAndChange(Reason.DECRYPTION_FAILED, enc -> dataMethod(enc).removeAttribute("Algorithm"));
    }

    @Test
    public void testKeyTransportAlgorithmOutsideTheListIsRefused() {
        for (final String algorithm : new String[] { "http://www.w3.org/2001/04/xmlenc#kw-aes128",
                "http://www.w3.org/2001/04/xmlenc#kw-tripledes", "http://www.w3.org/2009/xmlenc11#ECDH-ES", "urn:example:transport",
                "http://www.w3.org/2001/04/xmlenc#aes128-cbc", "" }) {
            final LoginResult.Rejected r =
                    encryptedControlAndChange(Reason.DECRYPTION_FAILED, enc -> keyMethod(enc).setAttribute("Algorithm", algorithm));
            assertDetailHas(r, "encryption algorithm is not allowed");
        }
    }

    @Test
    public void testKeyEncryptedForAnotherCertificateIsRefused() {
        final String message = encryptedResponse("cbc", true, enc -> {});
        accepted(login(configWithKey(), message));
        refused(Reason.DECRYPTION_FAILED, login(TestIdp.config().spPrivateKey(TestIdp.OTHER_KEY), message));
    }

    @Test
    public void testTruncatedAndCorruptedCiphertextIsRefused() {
        final List<Function<byte[], byte[]>> changes = List.of(b -> java.util.Arrays.copyOf(b, b.length - 5),
                b -> java.util.Arrays.copyOf(b, b.length - 16), b -> java.util.Arrays.copyOf(b, 8), b -> new byte[0], b -> {
                    final byte[] c = b.clone();
                    c[c.length - 1] ^= 0x55;
                    c[c.length - 17] ^= 0x55;
                    return c;
                });
        for (final Function<byte[], byte[]> change : changes) {
            encryptedControlAndChange(Reason.DECRYPTION_FAILED,
                    enc -> encode(dataCipherValue(enc), change.apply(decode(dataCipherValue(enc)))));
        }
    }

    @Test
    public void testGcmCiphertextThatWasChangedOrTruncatedIsRefused() {
        final List<Function<byte[], byte[]>> changes = List.of(b -> {
            final byte[] c = b.clone();
            c[c.length - 1] ^= 1;
            return c;
        }, b -> {
            final byte[] c = b.clone();
            c[14] ^= 1;
            return c;
        }, b -> java.util.Arrays.copyOf(b, b.length - 1), b -> java.util.Arrays.copyOf(b, 12), b -> new byte[0]);
        for (final Function<byte[], byte[]> change : changes) {
            encryptedControlAndChange("gcm", Reason.DECRYPTION_FAILED,
                    enc -> encode(dataCipherValue(enc), change.apply(decode(dataCipherValue(enc)))));
        }
    }

    @Test
    public void testTruncatedWrappedKeyIsRefused() {
        encryptedControlAndChange(Reason.DECRYPTION_FAILED, enc -> {
            final Element value = (Element) encryptedKey(enc).getElementsByTagNameNS(Names.NS_XENC, "CipherValue").item(0);
            encode(value, java.util.Arrays.copyOf(decode(value), 100));
        });
    }

    @Test
    public void testWrappedKeyThatIsNotBase64IsRefused() {
        encryptedControlAndChange(Reason.DECRYPTION_FAILED, enc -> {
            final Element value = (Element) encryptedKey(enc).getElementsByTagNameNS(Names.NS_XENC, "CipherValue").item(0);
            value.setTextContent("!!!");
        });
    }

    @Test
    public void testUnknownElementInsideTheEncryptedBlockIsRefused() {
        for (final String name : new String[] { "xenc:EncryptionProperties", "xenc:Transforms", "xenc:CipherReference" }) {
            encryptedControlAndChange(Reason.DECRYPTION_FAILED,
                    enc -> encryptedData(enc).appendChild(element(enc.getOwnerDocument(), Names.NS_XENC, name)));
        }
        encryptedControlAndChange(Reason.DECRYPTION_FAILED,
                enc -> encryptedData(enc).appendChild(element(enc.getOwnerDocument(), "urn:example", "x:Extra")));
    }

    @Test
    public void testAssertionAndEncryptedAssertionTogetherAreRefused() {
        controlAndChange(configWithKey(), Reason.MALFORMED, attack -> {
            final Element enc = ResponseTestSupport.encrypt(ResponseTestSupport.plainAssertion(), "cbc").element("EncryptedAssertion");
            final Document doc = ResponseTestSupport.responseWithEncryptedAssertion(enc, false);
            if (attack) {
                response(doc).appendChild(forgedAssertion(doc, "admin@example.com"));
            }
            signResponse(doc);
            return TestIdp.encode(doc);
        });
    }

    @Test
    public void testEncryptedAssertionInsideExtensionsIsRefused() {
        controlAndChange(configWithKey(), Reason.MALFORMED, attack -> {
            final Element enc = ResponseTestSupport.encrypt(ResponseTestSupport.plainAssertion(), "cbc").element("EncryptedAssertion");
            final Document doc = ResponseTestSupport.responseWithEncryptedAssertion(enc, false);
            if (attack) {
                final Element e = first(doc, Names.NS_SAML, "EncryptedAssertion");
                response(doc).removeChild(e);
                extensions(doc).appendChild(e);
            }
            signResponse(doc);
            return TestIdp.encode(doc);
        });
    }

    @Test
    public void testEncryptedAssertionChangedAfterTheResponseWasSignedIsRefused() {
        final Element enc = ResponseTestSupport.encrypt(ResponseTestSupport.plainAssertion(), "cbc").element("EncryptedAssertion");
        final Document doc = ResponseTestSupport.responseWithEncryptedAssertion(enc, true);
        accepted(login(configWithKey(), TestIdp.encode(doc)));
        final Element value = dataCipherValue(first(doc, Names.NS_SAML, "EncryptedAssertion"));
        encode(value,
                ResponseTestSupport.encrypt(ResponseTestSupport.plainAssertion(), "cbc").cipherValue().getBytes(StandardCharsets.UTF_8));
        refused(Reason.INVALID_SIGNATURE, login(configWithKey(), TestIdp.encode(doc)));
    }

    @Test
    public void testEncryptedAssertionInAnUnsignedResponseIsRefused() {
        // anyone can encrypt to the service provider's public key; only a signature makes the content trustworthy
        controlAndChange(configWithKey(), Reason.DECRYPTION_FAILED, attack -> {
            final Element enc = ResponseTestSupport.encrypt(ResponseTestSupport.plainAssertion(), "cbc").element("EncryptedAssertion");
            return TestIdp.encode(ResponseTestSupport.responseWithEncryptedAssertion(enc, !attack));
        });
    }

    @Test
    public void testEncryptedAssertionSignedByAnotherKeyIsRefused() {
        controlAndChange(configWithKey(), Reason.DECRYPTION_FAILED, attack -> {
            final Document doc = draft();
            TestIdp.sign(assertion(doc), attack ? TestIdp.OTHER_KEY : TestIdp.IDP_KEY, Names.RSA_SHA256, ResponseTestSupport.SHA256);
            final Element enc = ResponseTestSupport.encrypt(TestIdp.serialize(assertion(doc)), "cbc").element("EncryptedAssertion");
            final Document wrapped = ResponseTestSupport.responseWithEncryptedAssertion(enc, false);
            return TestIdp.encode(wrapped);
        });
    }

    private static String encryptedPlaintext(final String plain) {
        final Element enc = ResponseTestSupport.encrypt(plain, "cbc").element("EncryptedAssertion");
        return TestIdp.encode(ResponseTestSupport.responseWithEncryptedAssertion(enc, true));
    }

    @Test
    public void testDecryptedBlockThatIsNotAnAssertionIsRefused() {
        final String assertion = ResponseTestSupport.plainAssertion();
        accepted(login(configWithKey(), encryptedPlaintext(assertion)));
        refused(Reason.MALFORMED,
                login(configWithKey(), encryptedPlaintext("<saml:Issuer xmlns:saml=\"" + Names.NS_SAML + "\">x</saml:Issuer>")));
        refused(Reason.MALFORMED, login(configWithKey(), encryptedPlaintext("<a/>")));
    }

    @Test
    public void testDecryptedAssertionContainingAnotherAssertionIsRefused() {
        final Document control = draft();
        assertion(control).appendChild(element(control, Names.NS_SAML, "saml:Advice"));
        accepted(login(configWithKey(), encryptedPlaintext(TestIdp.serialize(assertion(control)))));
        final Document doc = draft();
        final Element advice = element(doc, Names.NS_SAML, "saml:Advice");
        advice.appendChild(forgedAssertion(doc, "admin@example.com"));
        assertion(doc).appendChild(advice);
        refused(Reason.MALFORMED, login(configWithKey(), encryptedPlaintext(TestIdp.serialize(assertion(doc)))));
    }

    @Test
    public void testDecryptedAssertionContainingAnEncryptedAssertionIsRefused() {
        final Document control = draft();
        assertion(control).appendChild(element(control, Names.NS_SAML, "saml:Advice"));
        accepted(login(configWithKey(), encryptedPlaintext(TestIdp.serialize(assertion(control)))));
        final Document doc = draft();
        final Element advice = element(doc, Names.NS_SAML, "saml:Advice");
        advice.appendChild(doc
                .importNode(ResponseTestSupport.encrypt(ResponseTestSupport.plainAssertion(), "cbc").element("EncryptedAssertion"), true));
        assertion(doc).appendChild(advice);
        refused(Reason.MALFORMED, login(configWithKey(), encryptedPlaintext(TestIdp.serialize(assertion(doc)))));
    }

    @Test
    public void testDecryptedAssertionWithADuplicateIdIsRefused() {
        final Document control = draft();
        final Element advice = element(control, Names.NS_SAML, "saml:Advice");
        advice.setAttribute("ID", "_advice1");
        assertion(control).appendChild(advice);
        accepted(login(configWithKey(), encryptedPlaintext(TestIdp.serialize(assertion(control)))));
        final Document doc = draft();
        final Element extra = element(doc, Names.NS_SAML, "saml:Advice");
        extra.setAttribute("ID", assertion(doc).getAttribute("ID"));
        assertion(doc).appendChild(extra);
        refused(Reason.MALFORMED, login(configWithKey(), encryptedPlaintext(TestIdp.serialize(assertion(doc)))));
    }

    @Test
    public void testDecryptedPlaintextThatIsHostileXmlIsRefused() {
        final String assertion = ResponseTestSupport.plainAssertion();
        accepted(login(configWithKey(), encryptedPlaintext(assertion)));
        try (Canary canary = new Canary()) {
            final String doctype = "<!DOCTYPE saml:Assertion [<!ENTITY xxe SYSTEM \"" + canary.url("/entity") + "\">]>";
            refused(Reason.DECRYPTION_FAILED, login(configWithKey(), encryptedPlaintext(doctype + assertion)));
            refused(Reason.DECRYPTION_FAILED,
                    login(configWithKey(), encryptedPlaintext(doctype + assertion.replace("alice@example.com", "&xxe;"))));
            assertEquals(0, canary.hits());
        }
        refused(Reason.DECRYPTION_FAILED, login(configWithKey(), encryptedPlaintext("not xml")));
        refused(Reason.DECRYPTION_FAILED,
                login(configWithKey(), encryptedPlaintext("<saml:Assertion xmlns:saml=\"" + Names.NS_SAML + "\">")));
    }

    @Test
    public void testDecryptedPlaintextThatIsTooDeepOrTooBigIsRefused() {
        final String assertion = ResponseTestSupport.plainAssertion();
        final String tail = "</saml:Assertion>";
        final String deep = assertion.replace(tail, nested(20000) + tail);
        refused(Reason.DECRYPTION_FAILED, login(configWithKey(), encryptedPlaintext(deep)));
        final String shallow = assertion.replace(tail, nested(10) + tail);
        accepted(login(configWithKey(), encryptedPlaintext(shallow)));
        final String wide = assertion.replace(tail, "<e/>".repeat(SafeXml.MAX_ELEMENTS + 1) + tail);
        refused(Reason.DECRYPTION_FAILED, login(configWithKey(), encryptedPlaintext(wide)));
    }

    // ---- failures that must never be exceptions ---------------------------------------------------------------------

    @Test
    public void testBrokenMessagesAreRefusedAsMalformed() {
        final String good = TestIdp.response().encoded();
        accepted(login(good));
        final String protocol = "<samlp:Response xmlns:samlp=\"" + Names.NS_SAMLP + "\"";
        for (final String text : new String[] { good.substring(0, good.length() / 2), good.substring(0, 8), good + "!", "====" + good,
                TestIdp.encode(protocol + "/>"), TestIdp.encode(protocol + " Version=\"2.0\" ID=\"\"/>"),
                TestIdp.encode(protocol + " Version=\"2.0\" ID=\"_x\"/>") }) {
            refused(Reason.MALFORMED, ServiceProvider.create(TestIdp.config().build()).finishLogin(text, PENDING));
        }
    }
}
