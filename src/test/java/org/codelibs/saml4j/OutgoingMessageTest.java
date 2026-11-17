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

import static org.codelibs.saml4j.LogoutTestSupport.only;
import static org.codelibs.saml4j.LogoutTestSupport.sent;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import org.codelibs.saml4j.LogoutTestSupport.Sent;
import org.codelibs.saml4j.internal.Messages;
import org.codelibs.saml4j.internal.Names;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class OutgoingMessageTest {

    private static final String MD = "urn:oasis:names:tc:SAML:2.0:metadata";

    private static final Pattern ID = Pattern.compile("_[0-9a-f]{32}");

    private static ServiceProvider sp(final SamlConfig.Builder b) {
        return ServiceProvider.create(b.build());
    }

    private static Element child(final Element parent, final String ns, final String local) {
        final List<Element> list = new ArrayList<>();
        for (org.w3c.dom.Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e && ns.equals(e.getNamespaceURI()) && local.equals(e.getLocalName())) {
                list.add(e);
            }
        }
        assertEquals(1, list.size(), local + " occurs " + list.size() + " times");
        return list.get(0);
    }

    // ---- startLogin ------------------------------------------------------------------------------------------------

    @Test
    public void testLoginUrlStartsWithTheSingleSignOnUrl() {
        final LoginStart s = sp(TestIdp.configWithLogout()).startLogin();
        assertTrue(s.redirectUrl().startsWith(TestIdp.SSO + "?SAMLRequest="), s.redirectUrl());
        final Sent sent = sent(s.redirectUrl());
        assertEquals(TestIdp.SSO, sent.endpoint);
        assertEquals('?', sent.separator);
    }

    @Test
    public void testAuthnRequestCarriesTheConfiguredValues() {
        final LoginStart s = sp(TestIdp.configWithLogout()).startLogin();
        final Document doc = sent(s.redirectUrl()).document();
        final Element root = doc.getDocumentElement();
        assertEquals(Names.NS_SAMLP, root.getNamespaceURI());
        assertEquals("AuthnRequest", root.getLocalName());
        assertEquals(s.requestId(), root.getAttribute("ID"));
        assertEquals("2.0", root.getAttribute("Version"));
        assertEquals(TestIdp.NOW.toString(), root.getAttribute("IssueInstant"));
        assertEquals(TestIdp.SSO, root.getAttribute("Destination"));
        assertEquals(TestIdp.ACS, root.getAttribute("AssertionConsumerServiceURL"));
        assertEquals(Names.BINDING_POST, root.getAttribute("ProtocolBinding"));
        assertEquals(TestIdp.SP, only(doc, Names.NS_SAML, "Issuer").getTextContent());
        final Element policy = only(doc, Names.NS_SAMLP, "NameIDPolicy");
        assertEquals(Names.NAMEID_UNSPECIFIED, policy.getAttribute("Format"));
        assertEquals("true", policy.getAttribute("AllowCreate"));
    }

    @Test
    public void testConfiguredNameIdFormatIsRequested() {
        final String format = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
        final Document doc = sent(sp(TestIdp.configWithLogout().nameIdFormat(format)).startLogin().redirectUrl()).document();
        assertEquals(format, only(doc, Names.NS_SAMLP, "NameIDPolicy").getAttribute("Format"));
    }

    @Test
    public void testAuthnRequestIsUnsignedByDefault() {
        final Sent sent = sent(sp(TestIdp.configWithLogout()).startLogin().redirectUrl());
        assertFalse(sent.raw.containsKey("Signature"));
        assertFalse(sent.raw.containsKey("SigAlg"));
        assertFalse(sent.raw.containsKey("RelayState"));
        assertEquals(List.of("SAMLRequest"), List.copyOf(sent.raw.keySet()));
    }

    @Test
    public void testAuthnRequestIsSignedWhenConfigured() {
        final Sent sent = sent(sp(TestIdp.configWithLogout().authnRequestSigned(true)).startLogin().redirectUrl());
        assertEquals(List.of("SAMLRequest", "SigAlg", "Signature"), List.copyOf(sent.raw.keySet()));
        assertEquals(Names.RSA_SHA256, sent.param("SigAlg"));
        assertTrue(sent.signedString().startsWith("SAMLRequest="));
        assertTrue(sent.signedString().endsWith("&SigAlg=" + sent.raw.get("SigAlg")));
        assertTrue(sent.signatureVerifies(TestIdp.SP_CERT));
        // the control for the checks above: the signature belongs to the SP key and to this text
        assertFalse(sent.signatureVerifies(TestIdp.OTHER_CERT));
        assertFalse(sent.signatureVerifies(TestIdp.IDP_CERT));
    }

    @Test
    public void testSignedAuthnRequestUsesTheConfiguredAlgorithm() {
        for (final String alg : new String[] { Names.RSA_SHA256, Names.RSA_SHA384, Names.RSA_SHA512 }) {
            final Sent sent =
                    sent(sp(TestIdp.configWithLogout().authnRequestSigned(true).signatureAlgorithm(alg)).startLogin().redirectUrl());
            assertEquals(alg, sent.param("SigAlg"));
            assertTrue(sent.signatureVerifies(TestIdp.SP_CERT), alg);
        }
    }

    @Test
    public void testSigningAnAuthnRequestNeedsAKey() {
        assertThrows(SamlConfigException.class, () -> TestIdp.config().authnRequestSigned(true).build());
        assertEquals(List.of("SAMLRequest"), List.copyOf(sent(sp(TestIdp.config()).startLogin().redirectUrl()).raw.keySet()));
    }

    @Test
    public void testDestinationThatHasAQueryGetsAnAmpersand() {
        final String sso = TestIdp.SSO + "?tenant=a&b=c";
        final LoginStart s = sp(TestIdp.configWithLogout().idpSingleSignOnServiceUrl(sso)).startLogin();
        assertTrue(s.redirectUrl().startsWith(sso + "&SAMLRequest="), s.redirectUrl());
        assertFalse(s.redirectUrl().substring(sso.length()).contains("?"));
        final Sent sent = sent(s.redirectUrl());
        assertEquals(sso, sent.endpoint);
        assertEquals('&', sent.separator);
        assertEquals(sso, sent.document().getDocumentElement().getAttribute("Destination"));

        // signed: the endpoint's own parameters are not part of the signed string
        final Sent signed =
                sent(sp(TestIdp.configWithLogout().idpSingleSignOnServiceUrl(sso).authnRequestSigned(true)).startLogin().redirectUrl());
        assertTrue(signed.signedString().startsWith("SAMLRequest="));
        assertTrue(signed.signatureVerifies(TestIdp.SP_CERT));

        // control: without a query the separator is a question mark
        assertEquals('?', sent(sp(TestIdp.configWithLogout()).startLogin().redirectUrl()).separator);
    }

    @Test
    public void testLogoutDestinationThatHasAQueryGetsAnAmpersand() {
        final String slo = TestIdp.SLO + "?tenant=a";
        final LogoutStart s = sp(TestIdp.configWithLogout().idpSingleLogoutServiceUrl(slo)).startLogout(NameId.of("alice"), null);
        assertTrue(s.redirectUrl().startsWith(slo + "&SAMLRequest="), s.redirectUrl());
        assertEquals(slo, sent(s.redirectUrl()).document().getDocumentElement().getAttribute("Destination"));
    }

    @Test
    public void testRequestedAuthnContextAppearsOnlyWhenConfigured() {
        final Document none = sent(sp(TestIdp.configWithLogout()).startLogin().redirectUrl()).document();
        assertEquals(0, TestIdp.all(none, Names.NS_SAMLP, "RequestedAuthnContext").size());
        assertEquals(0, TestIdp.all(none, Names.NS_SAML, "AuthnContextClassRef").size());

        final String ref = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
        final Document exact = sent(sp(TestIdp.configWithLogout().requestedAuthnContext(ref)).startLogin().redirectUrl()).document();
        assertEquals("exact", only(exact, Names.NS_SAMLP, "RequestedAuthnContext").getAttribute("Comparison"));
        assertEquals(ref, only(exact, Names.NS_SAML, "AuthnContextClassRef").getTextContent());

        final Document minimum =
                sent(sp(TestIdp.configWithLogout().requestedAuthnContext(ref).requestedAuthnContextComparison("minimum")).startLogin()
                        .redirectUrl()).document();
        assertEquals("minimum", only(minimum, Names.NS_SAMLP, "RequestedAuthnContext").getAttribute("Comparison"));
    }

    @Test
    public void testConfiguredValuesAreEscapedInTheAuthnRequest() {
        final String acs = "https://fess.example.com/sso/?a=1&b=2";
        final String ctx = "urn:x:<a>&\"b\"'c'";
        final String entity = "https://fess.example.com/sso/metadata?x=1&y=<2>\"'";
        final LoginStart s =
                sp(TestIdp.configWithLogout().assertionConsumerServiceUrl(acs).requestedAuthnContext(ctx).spEntityId(entity)).startLogin();
        final Document doc = sent(s.redirectUrl()).document();
        assertEquals(acs, doc.getDocumentElement().getAttribute("AssertionConsumerServiceURL"));
        assertEquals(ctx, only(doc, Names.NS_SAML, "AuthnContextClassRef").getTextContent());
        assertEquals(entity, only(doc, Names.NS_SAML, "Issuer").getTextContent());
    }

    @Test
    public void testIdsAreUniqueAndValidXmlIds() {
        final ServiceProvider sp = sp(TestIdp.configWithLogout());
        final Set<String> ids = new HashSet<>();
        for (int i = 0; i < 2000; i++) {
            final LoginStart s = sp.startLogin();
            assertTrue(ID.matcher(s.requestId()).matches(), s.requestId());
            assertTrue(ids.add(s.requestId()), "duplicate " + s.requestId());
            if (i < 20) {
                assertEquals(s.requestId(), sent(s.redirectUrl()).document().getDocumentElement().getAttribute("ID"));
            }
        }
        for (int i = 0; i < 500; i++) {
            final String id = sp.startLogout(NameId.of("alice"), null).requestId();
            assertTrue(ID.matcher(id).matches(), id);
            assertTrue(ids.add(id), "duplicate " + id);
        }
        for (int i = 0; i < 500; i++) {
            assertTrue(ids.add(Messages.newId()));
        }
    }

    // ---- startLogout -----------------------------------------------------------------------------------------------

    @Test
    public void testLogoutRequestCarriesTheSubject() {
        final NameId nameId =
                new NameId("alice@example.com", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "idp-qualifier", "sp-qualifier");
        final LogoutStart s = sp(TestIdp.configWithLogout()).startLogout(nameId, "_session1");
        assertTrue(s.redirectUrl().startsWith(TestIdp.SLO + "?SAMLRequest="), s.redirectUrl());
        final Sent sent = sent(s.redirectUrl());
        assertEquals(TestIdp.SLO, sent.endpoint);
        final Document doc = sent.document();
        final Element root = doc.getDocumentElement();
        assertEquals(Names.NS_SAMLP, root.getNamespaceURI());
        assertEquals("LogoutRequest", root.getLocalName());
        assertEquals(s.requestId(), root.getAttribute("ID"));
        assertEquals("2.0", root.getAttribute("Version"));
        assertEquals(TestIdp.NOW.toString(), root.getAttribute("IssueInstant"));
        assertEquals(TestIdp.NOW.plusSeconds(300).toString(), root.getAttribute("NotOnOrAfter"));
        assertEquals(TestIdp.SLO, root.getAttribute("Destination"));
        assertEquals(TestIdp.SP, only(doc, Names.NS_SAML, "Issuer").getTextContent());
        final Element name = only(doc, Names.NS_SAML, "NameID");
        assertEquals("alice@example.com", name.getTextContent());
        assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", name.getAttribute("Format"));
        assertEquals("idp-qualifier", name.getAttribute("NameQualifier"));
        assertEquals("sp-qualifier", name.getAttribute("SPNameQualifier"));
        assertEquals("_session1", only(doc, Names.NS_SAMLP, "SessionIndex").getTextContent());
    }

    @Test
    public void testLogoutRequestLeavesOutWhatIsNotGiven() {
        final ServiceProvider sp = sp(TestIdp.configWithLogout());
        for (final String index : new String[] { null, "" }) {
            final Document doc = sent(sp.startLogout(NameId.of("alice"), index).redirectUrl()).document();
            assertEquals(0, TestIdp.all(doc, Names.NS_SAMLP, "SessionIndex").size(), "index " + index);
            final Element name = only(doc, Names.NS_SAML, "NameID");
            assertEquals("alice", name.getTextContent());
            assertFalse(name.hasAttribute("Format"));
            assertFalse(name.hasAttribute("NameQualifier"));
            assertFalse(name.hasAttribute("SPNameQualifier"));
        }
        // the control: a session index is written when it is given
        assertEquals(1, TestIdp.all(sent(sp.startLogout(NameId.of("alice"), "_s").redirectUrl()).document(), Names.NS_SAMLP, "SessionIndex")
                .size());
    }

    @Test
    public void testLogoutRequestIsSignedWithTheServiceProviderKey() {
        final Sent sent = sent(sp(TestIdp.configWithLogout()).startLogout(NameId.of("alice"), "_s").redirectUrl());
        assertEquals(List.of("SAMLRequest", "SigAlg", "Signature"), List.copyOf(sent.raw.keySet()));
        assertEquals(Names.RSA_SHA256, sent.param("SigAlg"));
        assertTrue(sent.signatureVerifies(TestIdp.SP_CERT));
        assertFalse(sent.signatureVerifies(TestIdp.IDP_CERT));
        final Sent sha512 = sent(
                sp(TestIdp.configWithLogout().signatureAlgorithm(Names.RSA_SHA512)).startLogout(NameId.of("alice"), null).redirectUrl());
        assertEquals(Names.RSA_SHA512, sha512.param("SigAlg"));
        assertTrue(sha512.signatureVerifies(TestIdp.SP_CERT));
    }

    @Test
    public void testLogoutRequestValuesAreEscapedAndRoundTrip() {
        final String value = "a<b>&\"c'd\n e\r f\t g";
        final NameId nameId = new NameId(value, "urn:fmt:<f>&\"'", "nq<&>\"'", "spnq\n\"x\"");
        final String index = "_s<i>&\"'\n";
        final LogoutStart s = sp(TestIdp.configWithLogout()).startLogout(nameId, index);
        final Sent sent = sent(s.redirectUrl());
        // the text is well-formed XML (parse throws otherwise) ...
        final Document doc = sent.document();
        // ... and every value reads back unchanged
        final Element name = only(doc, Names.NS_SAML, "NameID");
        assertEquals(value, name.getTextContent());
        assertEquals("urn:fmt:<f>&\"'", name.getAttribute("Format"));
        assertEquals("nq<&>\"'", name.getAttribute("NameQualifier"));
        assertEquals("spnq\n\"x\"", name.getAttribute("SPNameQualifier"));
        assertEquals(index, only(doc, Names.NS_SAMLP, "SessionIndex").getTextContent());
        // the value never became markup
        assertEquals(0, TestIdp.all(doc, Names.NS_SAML, "b").size());
        assertTrue(sent.signatureVerifies(TestIdp.SP_CERT));
    }

    @Test
    public void testControlCharactersInANameIdAreReplacedNotCarried() {
        final Sent sent = sent(sp(TestIdp.configWithLogout()).startLogout(NameId.of("a\u0001b\u007fc"), null).redirectUrl());
        assertEquals("a?b?c", only(sent.document(), Names.NS_SAML, "NameID").getTextContent());
    }

    @Test
    public void testLogoutIsUnavailableWithoutASingleLogoutService() {
        final ServiceProvider noSlo = sp(TestIdp.config());
        assertThrows(IllegalStateException.class, () -> noSlo.startLogout(NameId.of("alice"), "_s"));
        // the control: with the service configured the same call works
        assertTrue(sp(TestIdp.configWithLogout()).startLogout(NameId.of("alice"), "_s").redirectUrl().startsWith(TestIdp.SLO));
    }

    @Test
    public void testLogoutWithoutAServiceProviderKeyIsNotSigned() {
        // Current behaviour: no key, no signature, and no complaint at configuration time.
        final SamlConfig.Builder b = TestIdp.config().idpSingleLogoutServiceUrl(TestIdp.SLO).singleLogoutServiceUrl(TestIdp.SLS);
        final Sent sent = sent(sp(b).startLogout(NameId.of("alice"), null).redirectUrl());
        assertEquals(List.of("SAMLRequest"), List.copyOf(sent.raw.keySet()));
    }

    // ---- metadata --------------------------------------------------------------------------------------------------

    private static Element metadataRoot(final ServiceProvider sp) {
        final Element root = TestIdp.parse(sp.metadata()).getDocumentElement();
        assertEquals(MD, root.getNamespaceURI());
        assertEquals("EntityDescriptor", root.getLocalName());
        return root;
    }

    private static String certificateText(final java.security.cert.X509Certificate cert) {
        try {
            return Base64.getEncoder().encodeToString(cert.getEncoded());
        } catch (final CertificateEncodingException e) {
            throw new AssertionError(e);
        }
    }

    @Test
    public void testMetadataDescribesTheEndpoints() {
        final Element root = metadataRoot(sp(TestIdp.configWithLogout()));
        assertEquals(TestIdp.SP, root.getAttribute("entityID"));
        final Element sso = child(root, MD, "SPSSODescriptor");
        assertEquals(Names.NS_SAMLP, sso.getAttribute("protocolSupportEnumeration"));
        assertEquals("false", sso.getAttribute("AuthnRequestsSigned"));
        assertEquals("false", sso.getAttribute("WantAssertionsSigned"));

        final Element acs = child(sso, MD, "AssertionConsumerService");
        assertEquals(Names.BINDING_POST, acs.getAttribute("Binding"));
        assertEquals(TestIdp.ACS, acs.getAttribute("Location"));
        assertEquals("1", acs.getAttribute("index"));
        assertEquals("true", acs.getAttribute("isDefault"));

        final org.w3c.dom.NodeList sls = sso.getElementsByTagNameNS(MD, "SingleLogoutService");
        assertEquals(2, sls.getLength());
        assertEquals(Names.BINDING_REDIRECT, ((Element) sls.item(0)).getAttribute("Binding"));
        assertEquals(Names.BINDING_POST, ((Element) sls.item(1)).getAttribute("Binding"));
        assertEquals(TestIdp.SLS, ((Element) sls.item(0)).getAttribute("Location"));
        assertEquals(TestIdp.SLS, ((Element) sls.item(1)).getAttribute("Location"));

        assertEquals(Names.NAMEID_UNSPECIFIED, child(sso, MD, "NameIDFormat").getTextContent());
    }

    @Test
    public void testMetadataReflectsSigningSettings() {
        final Element on = child(metadataRoot(sp(TestIdp.configWithLogout().authnRequestSigned(true).wantAssertionsSigned(true))), MD,
                "SPSSODescriptor");
        assertEquals("true", on.getAttribute("AuthnRequestsSigned"));
        assertEquals("true", on.getAttribute("WantAssertionsSigned"));
        final Element off = child(metadataRoot(sp(TestIdp.configWithLogout())), MD, "SPSSODescriptor");
        assertEquals("false", off.getAttribute("AuthnRequestsSigned"));
        assertEquals("false", off.getAttribute("WantAssertionsSigned"));
    }

    @Test
    public void testMetadataHasNoSingleLogoutServiceWhenNotConfigured() {
        final Element sso = child(metadataRoot(sp(TestIdp.config())), MD, "SPSSODescriptor");
        assertEquals(0, sso.getElementsByTagNameNS(MD, "SingleLogoutService").getLength());
        // the control: it is there when configured
        assertEquals(2,
                child(metadataRoot(sp(TestIdp.configWithLogout())), MD, "SPSSODescriptor").getElementsByTagNameNS(MD, "SingleLogoutService")
                        .getLength());
    }

    @Test
    public void testMetadataPublishesTheServiceProviderCertificateForSigningAndEncryption() {
        final Element sso = child(metadataRoot(sp(TestIdp.configWithLogout())), MD, "SPSSODescriptor");
        final org.w3c.dom.NodeList keys = sso.getElementsByTagNameNS(MD, "KeyDescriptor");
        assertEquals(2, keys.getLength());
        final Set<String> uses = new HashSet<>();
        for (int i = 0; i < keys.getLength(); i++) {
            final Element key = (Element) keys.item(i);
            uses.add(key.getAttribute("use"));
            assertEquals(certificateText(TestIdp.SP_CERT),
                    key.getElementsByTagNameNS(Names.NS_DS, "X509Certificate").item(0).getTextContent());
        }
        assertEquals(Set.of("signing", "encryption"), uses);
    }

    @Test
    public void testMetadataHasNoKeyDescriptorWithoutACertificate() {
        final Element sso = child(metadataRoot(sp(TestIdp.config())), MD, "SPSSODescriptor");
        assertEquals(0, sso.getElementsByTagNameNS(MD, "KeyDescriptor").getLength());
        assertFalse(sp(TestIdp.config()).metadata().contains("X509Certificate"));
        // the control: the same configuration plus the certificate has them
        assertEquals(2,
                child(metadataRoot(sp(TestIdp.config().spCertificate(TestIdp.SP_CERT))), MD, "SPSSODescriptor")
                        .getElementsByTagNameNS(MD, "KeyDescriptor")
                        .getLength());
    }

    @Test
    public void testMetadataElementsAreInSchemaOrder() {
        final Element sso = child(metadataRoot(sp(TestIdp.configWithLogout())), MD, "SPSSODescriptor");
        final List<String> names = new ArrayList<>();
        for (org.w3c.dom.Node n = sso.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e) {
                names.add(e.getLocalName());
            }
        }
        assertEquals(List.of("KeyDescriptor", "KeyDescriptor", "SingleLogoutService", "SingleLogoutService", "NameIDFormat",
                "AssertionConsumerService"), names);
    }

    @Test
    public void testMetadataValuesAreEscaped() {
        final String entity = "https://fess.example.com/sso/metadata?x=1&y=<2>\"'";
        final String acs = "https://fess.example.com/sso/?a=1&b=2";
        final String format = "urn:fmt:<f>&\"'";
        final Element root =
                metadataRoot(sp(TestIdp.configWithLogout().spEntityId(entity).assertionConsumerServiceUrl(acs).nameIdFormat(format)));
        assertEquals(entity, root.getAttribute("entityID"));
        final Element sso = child(root, MD, "SPSSODescriptor");
        assertEquals(acs, child(sso, MD, "AssertionConsumerService").getAttribute("Location"));
        assertEquals(format, child(sso, MD, "NameIDFormat").getTextContent());
    }

    @Test
    public void testMetadataIsStable() {
        final ServiceProvider sp = sp(TestIdp.configWithLogout());
        assertEquals(sp.metadata(), sp.metadata());
        assertNotEquals("", sp.metadata());
    }
}
