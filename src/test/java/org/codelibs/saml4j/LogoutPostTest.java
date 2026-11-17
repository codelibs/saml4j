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
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.PrivateKey;

import org.codelibs.saml4j.LogoutOutcome.Action;
import org.codelibs.saml4j.internal.Names;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

public class LogoutPostTest {

    private static final String DIGEST = "http://www.w3.org/2001/04/xmlenc#sha256";

    private static ServiceProvider sp() {
        return ServiceProvider.create(TestIdp.configWithLogout().build());
    }

    private static String signed(final String xml, final PrivateKey key) {
        final Document doc = TestIdp.parse(xml);
        TestIdp.sign(doc.getDocumentElement(), key, Names.RSA_SHA256, DIGEST);
        return TestIdp.encode(doc);
    }

    private static String request(final String id, final String nameId) {
        return TestIdp.logoutRequestXml(id, nameId, null);
    }

    private static LogoutOutcome handle(final ServiceProvider sp, final String samlRequest, final String samlResponse) {
        return sp.handleLogoutPost(samlRequest, samlResponse, null, "alice@example.com", null);
    }

    @Test
    public void testSignedRequestNamingTheSessionEndsIt() {
        final LogoutOutcome o = handle(sp(), signed(request("_p1", "alice@example.com"), TestIdp.IDP_KEY), null);
        assertEquals(Action.END_SESSION, o.action(), o.toString());
        assertTrue(o.redirectUrl().startsWith(TestIdp.SLO + "?SAMLResponse="));
    }

    @Test
    public void testSignedRequestNamingAnotherUserKeepsTheSession() {
        final LogoutOutcome o = handle(sp(), signed(request("_p2", "bob@example.com"), TestIdp.IDP_KEY), null);
        assertEquals(Action.KEEP_SESSION, o.action(), o.toString());
        assertNotNull(o.redirectUrl());
    }

    @Test
    public void testUnsignedRequestIsRefusedUnlessSigningIsNotRequired() {
        final String unsigned = TestIdp.encode(request("_p3", "alice@example.com"));
        assertEquals(Reason.NOT_SIGNED, handle(sp(), unsigned, null).reason());
        final ServiceProvider relaxed = ServiceProvider.create(TestIdp.configWithLogout().wantLogoutSigned(false).build());
        assertEquals(Action.END_SESSION, handle(relaxed, unsigned, null).action());
    }

    @Test
    public void testRequestSignedByAnotherKeyIsRefused() {
        final LogoutOutcome o = handle(sp(), signed(request("_p4", "alice@example.com"), TestIdp.OTHER_KEY), null);
        assertEquals(Action.REJECTED, o.action());
        assertEquals(Reason.INVALID_SIGNATURE, o.reason());
    }

    @Test
    public void testBadSignatureIsRefusedEvenWhenSigningIsNotRequired() {
        final ServiceProvider relaxed = ServiceProvider.create(TestIdp.configWithLogout().wantLogoutSigned(false).build());
        final LogoutOutcome o = handle(relaxed, signed(request("_p5", "alice@example.com"), TestIdp.OTHER_KEY), null);
        assertEquals(Reason.INVALID_SIGNATURE, o.reason());
    }

    @Test
    public void testContentChangedAfterSigningIsRefused() {
        final String message = signed(request("_p6", "alice@example.com"), TestIdp.IDP_KEY);
        final String xml = new String(java.util.Base64.getDecoder().decode(message), java.nio.charset.StandardCharsets.UTF_8);
        final String changed = TestIdp.encode(xml.replace("alice@example.com", "bob@example.com"));
        assertEquals(Reason.INVALID_SIGNATURE, handle(sp(), changed, null).reason());
        assertEquals(Action.END_SESSION, handle(sp(), message, null).action());
    }

    @Test
    public void testExactlyOneParameterIsRequired() {
        final String m = signed(request("_p7", "alice@example.com"), TestIdp.IDP_KEY);
        assertEquals(Reason.BAD_REQUEST, handle(sp(), m, m).reason());
        assertEquals(Reason.BAD_REQUEST, handle(sp(), null, null).reason());
        assertEquals(Reason.BAD_REQUEST, handle(sp(), " ", "").reason());
    }

    @Test
    public void testDuplicateIdsAreRefused() {
        final Document doc = TestIdp.parse(request("_p12", "alice@example.com"));
        doc.getDocumentElement().getElementsByTagNameNS(Names.NS_SAML, "Issuer").item(0).getAttributes();
        ((org.w3c.dom.Element) doc.getDocumentElement().getElementsByTagNameNS(Names.NS_SAML, "NameID").item(0)).setAttribute("ID", "_p12");
        final LogoutOutcome o = handle(sp(), TestIdp.encode(doc), null);
        assertEquals(Reason.MALFORMED, o.reason(), o.toString());
        final Document control = TestIdp.parse(request("_p13", "alice@example.com"));
        ((org.w3c.dom.Element) control.getDocumentElement().getElementsByTagNameNS(Names.NS_SAML, "NameID").item(0)).setAttribute("ID",
                "_other");
        assertEquals(Action.END_SESSION, handle(relaxed(), TestIdp.encode(control), null).action());
    }

    private static ServiceProvider relaxed() {
        return ServiceProvider.create(TestIdp.configWithLogout().wantLogoutSigned(false).build());
    }

    @Test
    public void testReplayIsRefused() {
        final ServiceProvider sp = sp();
        final String m = signed(request("_p8", "alice@example.com"), TestIdp.IDP_KEY);
        assertEquals(Action.END_SESSION, handle(sp, m, null).action());
        assertEquals(Reason.REPLAYED, handle(sp, m, null).reason());
    }

    @Test
    public void testSignedLogoutResponseNeverEndsTheSession() {
        final LogoutOutcome ok = handle(sp(), null, signed(TestIdp.logoutResponseXml("_p9", Names.STATUS_SUCCESS), TestIdp.IDP_KEY));
        assertEquals(Action.KEEP_SESSION, ok.action(), ok.toString());
        assertNull(ok.redirectUrl());
        final LogoutOutcome failed = handle(sp(), null,
                signed(TestIdp.logoutResponseXml("_p10", "urn:oasis:names:tc:SAML:2.0:status:Responder"), TestIdp.IDP_KEY));
        assertEquals(Reason.STATUS_NOT_SUCCESS, failed.reason());
    }

    @Test
    public void testRelayStateIsEchoedToTheIdentityProvider() {
        final LogoutOutcome o = sp().handleLogoutPost(signed(request("_p11", "alice@example.com"), TestIdp.IDP_KEY), null, "relay 1",
                "alice@example.com", null);
        assertTrue(o.redirectUrl().contains("&RelayState=relay%201"), o.redirectUrl());
    }

    @Test
    public void testNotConfiguredIsUnsupported() {
        final ServiceProvider noLogout = ServiceProvider.create(TestIdp.config().build());
        assertEquals(Reason.UNSUPPORTED, noLogout.handleLogoutPost("x", null, null, null, null).reason());
    }
}
