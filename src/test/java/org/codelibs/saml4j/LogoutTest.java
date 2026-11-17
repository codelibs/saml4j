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

import static org.codelibs.saml4j.LogoutTestSupport.INDEX;
import static org.codelibs.saml4j.LogoutTestSupport.USER;
import static org.codelibs.saml4j.LogoutTestSupport.assertEnded;
import static org.codelibs.saml4j.LogoutTestSupport.assertKeptAndAnswered;
import static org.codelibs.saml4j.LogoutTestSupport.assertRejected;
import static org.codelibs.saml4j.LogoutTestSupport.handle;
import static org.codelibs.saml4j.LogoutTestSupport.sent;
import static org.codelibs.saml4j.LogoutTestSupport.sp;
import static org.codelibs.saml4j.LogoutTestSupport.spAcceptingUnsigned;
import static org.codelibs.saml4j.LogoutTestSupport.text;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.regex.Pattern;

import org.codelibs.saml4j.LogoutOutcome.Action;
import org.codelibs.saml4j.LogoutTestSupport.Request;
import org.codelibs.saml4j.LogoutTestSupport.Sent;
import org.codelibs.saml4j.internal.Names;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

public class LogoutTest {

    private static final Pattern LINE_BREAK = Pattern.compile("[\\r\\n\\u0085\\u2028\\u2029]");

    private static final Pattern ANY_CONTROL = Pattern.compile("[\\p{Cntrl}\\u0085\\u2028\\u2029]");

    /** Asserts a valid request is still accepted by this provider; the control for the refusals below. */
    private static void control(final ServiceProvider sp) {
        assertEnded(handle(sp, new Request("_control").signed()));
    }

    private static Instant at(final long secondsFromNow) {
        return TestIdp.NOW.plusSeconds(secondsFromNow);
    }

    // ---- a request that names the session -------------------------------------------------------------------------

    @Test
    public void testRequestNamingTheSessionEndsItAndIsAnswered() {
        final ServiceProvider sp = sp();
        final LogoutOutcome o = handle(sp, new Request("_lr1").signed());
        assertEnded(o);
        assertEquals(Action.END_SESSION, o.action());

        final Sent answer = sent(o.redirectUrl());
        assertEquals(TestIdp.SLO, answer.endpoint);
        assertEquals('?', answer.separator);
        assertEquals("SAMLResponse", answer.messageName());
        assertFalse(answer.raw.containsKey("RelayState"));

        final Document doc = answer.document();
        assertEquals(Names.NS_SAMLP, doc.getDocumentElement().getNamespaceURI());
        assertEquals("LogoutResponse", doc.getDocumentElement().getLocalName());
        assertEquals("2.0", doc.getDocumentElement().getAttribute("Version"));
        assertEquals("_lr1", doc.getDocumentElement().getAttribute("InResponseTo"));
        assertEquals(TestIdp.SLO, doc.getDocumentElement().getAttribute("Destination"));
        assertEquals(TestIdp.NOW.toString(), doc.getDocumentElement().getAttribute("IssueInstant"));
        assertTrue(doc.getDocumentElement().getAttribute("ID").startsWith("_"));
        assertNotEquals("_lr1", doc.getDocumentElement().getAttribute("ID"));
        assertEquals(TestIdp.SP, text(doc, Names.NS_SAML, "Issuer"));
        assertEquals(Names.STATUS_SUCCESS, LogoutTestSupport.only(doc, Names.NS_SAMLP, "StatusCode").getAttribute("Value"));
    }

    @Test
    public void testAnswerIsSignedWithTheServiceProviderKey() {
        final LogoutOutcome o = handle(sp(), new Request("_lr1").signed());
        assertEnded(o);
        final Sent answer = sent(o.redirectUrl());
        assertEquals(Names.RSA_SHA256, answer.param("SigAlg"));
        assertTrue(answer.signatureVerifies(TestIdp.SP_CERT));
        assertFalse(answer.signatureVerifies(TestIdp.IDP_CERT));
        assertFalse(answer.signatureVerifies(TestIdp.OTHER_CERT));
        assertTrue(answer.signedString().startsWith("SAMLResponse="));
        assertTrue(answer.signedString().endsWith("&SigAlg=" + answer.raw.get("SigAlg")));
    }

    @Test
    public void testAnswerUsesTheConfiguredSignatureAlgorithm() {
        final ServiceProvider sp = sp(TestIdp.configWithLogout().signatureAlgorithm(Names.RSA_SHA512));
        final LogoutOutcome o = handle(sp, new Request("_lr1").signed());
        assertEnded(o);
        final Sent answer = sent(o.redirectUrl());
        assertEquals(Names.RSA_SHA512, answer.param("SigAlg"));
        assertTrue(answer.signatureVerifies(TestIdp.SP_CERT));
    }

    @Test
    public void testAnswerGetsAFreshIdEachTime() {
        final ServiceProvider sp = sp();
        final String a = sent(handle(sp, new Request("_a").signed()).redirectUrl()).document().getDocumentElement().getAttribute("ID");
        final String b = sent(handle(sp, new Request("_b").signed()).redirectUrl()).document().getDocumentElement().getAttribute("ID");
        assertNotEquals(a, b);
    }

    // ---- a request that does not name the session -----------------------------------------------------------------

    @Test
    public void testRequestNamingAnotherUserKeepsTheSessionButIsAnswered() {
        final ServiceProvider sp = sp();
        control(sp);
        final LogoutOutcome o = handle(sp, new Request("_lr1").nameId("bob@example.com").signed());
        assertKeptAndAnswered(o);
        final Sent answer = sent(o.redirectUrl());
        assertEquals("_lr1", answer.document().getDocumentElement().getAttribute("InResponseTo"));
        assertTrue(answer.signatureVerifies(TestIdp.SP_CERT));
    }

    @Test
    public void testNameIdIsComparedExactly() {
        final ServiceProvider sp = sp();
        control(sp);
        assertKeptAndAnswered(handle(sp, new Request("_lr1").nameId("Alice@Example.com").signed()));
        assertKeptAndAnswered(handle(sp, new Request("_lr2").nameId(" alice@example.com ").signed()));
        assertKeptAndAnswered(handle(sp, new Request("_lr3").nameId("alice").signed()));
        assertKeptAndAnswered(handle(sp, new Request("_lr4").nameId("alice@example.com.evil").signed()));
    }

    @Test
    public void testSessionThatIsNotSamlIsKept() {
        final ServiceProvider sp = sp();
        control(sp);
        final LogoutOutcome o = sp.handleLogout("GET", new Request("_lr1").signed(), null, null);
        assertKeptAndAnswered(o);
        assertTrue(sent(o.redirectUrl()).signatureVerifies(TestIdp.SP_CERT));
    }

    @Test
    public void testSessionIndexMismatchKeepsTheSession() {
        final ServiceProvider sp = sp();
        control(sp);
        assertKeptAndAnswered(handle(sp, new Request("_lr1").sessionIndexes("_other").signed()));
    }

    @Test
    public void testSessionIndexAmongSeveralEndsTheSession() {
        final ServiceProvider sp = sp();
        assertEnded(handle(sp, new Request("_lr1").sessionIndexes("_other", INDEX, "_third").signed()));
        assertKeptAndAnswered(handle(sp, new Request("_lr2").sessionIndexes("_other", "_third").signed()));
    }

    @Test
    public void testRequestWithoutSessionIndexEndsEverySessionOfTheUser() {
        final ServiceProvider sp = sp();
        assertEnded(handle(sp, new Request("_lr1").sessionIndexes().signed()));
        assertKeptAndAnswered(handle(sp, new Request("_lr2").sessionIndexes().nameId("bob@example.com").signed()));
    }

    /** A session that has no SessionIndex is not named by a request that names an index. */
    @Test
    public void testSessionWithoutIndexIsNotEndedByARequestNamingAnIndex() {
        final ServiceProvider sp = sp();
        assertKeptAndAnswered(sp.handleLogout("GET", new Request("_lr1").sessionIndexes("_any").signed(), USER, null));
        assertEnded(sp.handleLogout("GET", new Request("_lr2").sessionIndexes().signed(), USER, null));
    }

    // ---- signatures ------------------------------------------------------------------------------------------------

    @Test
    public void testUnsignedRequestIsRefusedByDefault() {
        final ServiceProvider sp = sp();
        control(sp);
        assertRejected(Reason.NOT_SIGNED, handle(sp, new Request("_lr1").unsigned()));
    }

    @Test
    public void testUnsignedRequestIsHandledWhenSignatureIsNotRequired() {
        final ServiceProvider sp = spAcceptingUnsigned();
        assertEnded(handle(sp, new Request("_lr1").unsigned()));
        assertKeptAndAnswered(handle(sp, new Request("_lr2").nameId("bob@example.com").unsigned()));
        // the answer is still signed by this service provider
        assertTrue(sent(handle(sp, new Request("_lr3").unsigned()).redirectUrl()).signatureVerifies(TestIdp.SP_CERT));
    }

    @Test
    public void testRefusedRequestDoesNotUseUpItsId() {
        final ServiceProvider sp = sp();
        final Request r = new Request("_lr1");
        assertRejected(Reason.NOT_SIGNED, handle(sp, r.unsigned()));
        assertEnded(handle(sp, r.signed()));
    }

    @Test
    public void testBadSignatureIsRefusedWhetherOrNotSignaturesAreRequired() {
        for (final ServiceProvider sp : new ServiceProvider[] { sp(), spAcceptingUnsigned() }) {
            control(sp);
            final String byOther = LogoutTestSupport.redirectQuery("SAMLRequest", new Request("_lr1").xml(), null, TestIdp.OTHER_KEY);
            assertRejected(Reason.INVALID_SIGNATURE, handle(sp, byOther));
            final String bySp = LogoutTestSupport.redirectQuery("SAMLRequest", new Request("_lr2").xml(), null, TestIdp.SP_KEY);
            assertRejected(Reason.INVALID_SIGNATURE, handle(sp, bySp));
        }
    }

    @Test
    public void testSignatureDoesNotCoverAReplacedMessageOrRelayState() {
        for (final ServiceProvider sp : new ServiceProvider[] { sp(), spAcceptingUnsigned() }) {
            final String first = new Request("_lr1").nameId("bob@example.com").signed("keep");
            final String other = LogoutTestSupport.redirectQuery("SAMLRequest", new Request("_lr2").xml(), "keep", null);
            final String swapped = other.substring(0, other.indexOf("&RelayState=")) + first.substring(first.indexOf("&RelayState="));
            assertRejected(Reason.INVALID_SIGNATURE, handle(sp, swapped));

            final String relayChanged = first.replace("RelayState=keep", "RelayState=elsewhere");
            assertRejected(Reason.INVALID_SIGNATURE, handle(sp, relayChanged));

            // the signed original is fine
            assertKeptAndAnswered(handle(sp, first));
        }
    }

    // ---- request shape ---------------------------------------------------------------------------------------------

    @Test
    public void testRequestAndResponseTogetherAreRefused() {
        final ServiceProvider sp = spAcceptingUnsigned();
        final String request = new Request("_lr1").unsigned();
        final String response =
                LogoutTestSupport.redirectQuery("SAMLResponse", TestIdp.logoutResponseXml("_lresp", Names.STATUS_SUCCESS), null, null);
        assertEnded(handle(sp, request));
        assertRejected(Reason.BAD_REQUEST, handle(sp, new Request("_lr2").unsigned() + "&" + response));
        assertRejected(Reason.BAD_REQUEST, handle(sp, response + "&" + new Request("_lr3").unsigned()));
        // signed messages are refused the same way
        assertRejected(Reason.BAD_REQUEST, handle(sp(), new Request("_lr4").signed() + "&" + LogoutTestSupport.redirectQuery("SAMLResponse",
                TestIdp.logoutResponseXml("_lresp2", Names.STATUS_SUCCESS), null, TestIdp.IDP_KEY)));
    }

    @Test
    public void testQueryWithNeitherMessageIsRefused() {
        final ServiceProvider sp = sp();
        control(sp);
        assertRejected(Reason.BAD_REQUEST, handle(sp, "RelayState=x"));
        assertRejected(Reason.BAD_REQUEST, handle(sp, "foo=bar&baz=1"));
        assertRejected(Reason.BAD_REQUEST, handle(sp, null));
        assertRejected(Reason.BAD_REQUEST, handle(sp, ""));
    }

    @Test
    public void testOnlyGetIsAccepted() {
        final ServiceProvider sp = sp();
        final String query = new Request("_lr1").signed();
        assertRejected(Reason.BAD_REQUEST, sp.handleLogout("POST", query, USER, INDEX));
        assertRejected(Reason.BAD_REQUEST, sp.handleLogout("PUT", query, USER, INDEX));
        assertRejected(Reason.BAD_REQUEST, sp.handleLogout(null, query, USER, INDEX));
        assertEnded(sp.handleLogout("GET", query, USER, INDEX));
    }

    @Test
    public void testLogoutIsUnsupportedWithoutASingleLogoutService() {
        final ServiceProvider noSlo = sp(TestIdp.config());
        assertRejected(Reason.UNSUPPORTED, handle(noSlo, new Request("_lr1").signed()));
        assertRejected(Reason.UNSUPPORTED, noSlo.handleLogout("POST", new Request("_lr2").signed(), USER, INDEX));
        assertEnded(handle(sp(), new Request("_lr1").signed()));
    }

    @Test
    public void testRequestWithTheWrongRootIsRefused() {
        final ServiceProvider sp = sp();
        control(sp);
        final String xml = TestIdp.logoutResponseXml("_lr1", Names.STATUS_SUCCESS);
        assertRejected(Reason.MALFORMED, handle(sp, LogoutTestSupport.redirectQuery("SAMLRequest", xml, null, TestIdp.IDP_KEY)));
    }

    @Test
    public void testRequestStructureIsChecked() {
        final ServiceProvider sp = sp();
        control(sp);

        final Request wrongVersion = new Request("_lr1");
        wrongVersion.version = "1.1";
        assertRejected(Reason.MALFORMED, handle(sp, wrongVersion.signed()));

        final Request noVersion = new Request("_lr2");
        noVersion.version = null;
        assertRejected(Reason.MALFORMED, handle(sp, noVersion.signed()));

        assertRejected(Reason.MALFORMED, handle(sp, new Request(null).signed()));
        assertRejected(Reason.MALFORMED, handle(sp, new Request("").signed()));

        final Request noName = new Request("_lr3");
        noName.nameId = null;
        assertRejected(Reason.MALFORMED, handle(sp, noName.signed()));
        assertRejected(Reason.MALFORMED, handle(sp, new Request("_lr4").nameId("  ").signed()));

        final Request twoNames = new Request("_lr5");
        final String xml = twoNames.xml().replace("</saml:NameID>", "</saml:NameID><saml:NameID>bob@example.com</saml:NameID>");
        assertRejected(Reason.MALFORMED, handle(sp, LogoutTestSupport.redirectQuery("SAMLRequest", xml, null, TestIdp.IDP_KEY)));

        final Request badInstant = new Request("_lr6");
        badInstant.issueInstant = "yesterday";
        assertRejected(Reason.MALFORMED, handle(sp, badInstant.signed()));

        final Request badNotOnOrAfter = new Request("_lr7");
        badNotOnOrAfter.notOnOrAfter = "soon";
        assertRejected(Reason.MALFORMED, handle(sp, badNotOnOrAfter.signed()));
    }

    // ---- issuer and destination ------------------------------------------------------------------------------------

    @Test
    public void testWrongIssuerIsRefused() {
        final ServiceProvider sp = sp();
        control(sp);
        final Request r = new Request("_lr1");
        r.issuer = "https://evil.example.com/metadata";
        assertRejected(Reason.WRONG_ISSUER, handle(sp, r.signed()));
        r.id = "_lr2";
        r.issuer = TestIdp.IDP + "/";
        assertRejected(Reason.WRONG_ISSUER, handle(sp, r.signed()));
        r.id = "_lr3";
        r.issuer = TestIdp.IDP.toUpperCase();
        assertRejected(Reason.WRONG_ISSUER, handle(sp, r.signed()));
    }

    @Test
    public void testMissingIssuerIsRefused() {
        final ServiceProvider sp = sp();
        control(sp);
        final Request r = new Request("_lr1");
        r.issuer = null;
        assertRejected(Reason.MALFORMED, handle(sp, r.signed()));
    }

    @Test
    public void testWrongDestinationIsRefused() {
        final ServiceProvider sp = sp();
        control(sp);
        for (final String destination : new String[] { "https://fess.example.com/sso/other", TestIdp.SLS + "/", TestIdp.ACS, TestIdp.SLO,
                TestIdp.SLS.toUpperCase(), "" }) {
            final Request r = new Request("_d" + destination.hashCode());
            r.destination = destination;
            assertRejected(Reason.WRONG_DESTINATION, handle(sp, r.signed()));
        }
    }

    @Test
    public void testMissingDestinationIsRefusedWhenSigned() {
        final ServiceProvider sp = sp();
        control(sp);
        final Request r = new Request("_lr1");
        r.destination = null;
        assertRejected(Reason.WRONG_DESTINATION, handle(sp, r.signed()));
    }

    @Test
    public void testMissingDestinationIsAllowedOnlyOnAnUnsignedMessage() {
        final ServiceProvider sp = spAcceptingUnsigned();
        final Request r = new Request("_lr1");
        r.destination = null;
        assertEnded(handle(sp, r.unsigned()));
        // the same message, signed, is refused
        r.id = "_lr2";
        assertRejected(Reason.WRONG_DESTINATION, handle(sp, r.signed()));
        // and a wrong destination is refused unsigned as well
        r.id = "_lr3";
        r.destination = "https://fess.example.com/sso/other";
        assertRejected(Reason.WRONG_DESTINATION, handle(sp, r.unsigned()));
    }

    // ---- time ------------------------------------------------------------------------------------------------------

    @Test
    public void testIssueInstantTooOldIsRefused() {
        final ServiceProvider sp = sp(TestIdp.configWithLogout().clockDriftSeconds(120));
        final Request r = new Request("_lr1");
        // lifetime 300 s plus drift 120 s: the last acceptable instant is 419 s ago
        r.issueInstant = at(-419).toString();
        assertEnded(handle(sp, r.signed()));
        r.id = "_lr2";
        r.issueInstant = at(-420).toString();
        assertRejected(Reason.EXPIRED, handle(sp, r.signed()));
        r.id = "_lr3";
        r.issueInstant = at(-86_400).toString();
        assertRejected(Reason.EXPIRED, handle(sp, r.signed()));
    }

    @Test
    public void testIssueInstantInTheFutureIsRefused() {
        final ServiceProvider sp = sp(TestIdp.configWithLogout().clockDriftSeconds(120));
        final Request r = new Request("_lr1");
        r.issueInstant = at(120).toString();
        assertEnded(handle(sp, r.signed()));
        r.id = "_lr2";
        r.issueInstant = at(121).toString();
        assertRejected(Reason.EXPIRED, handle(sp, r.signed()));
        r.id = "_lr3";
        r.issueInstant = at(86_400).toString();
        assertRejected(Reason.EXPIRED, handle(sp, r.signed()));
    }

    @Test
    public void testClockDriftSettingIsHonoured() {
        final ServiceProvider strict = sp(TestIdp.configWithLogout().clockDriftSeconds(0));
        final Request r = new Request("_lr1");
        r.issueInstant = at(0).toString();
        assertEnded(handle(strict, r.signed()));
        r.id = "_lr2";
        r.issueInstant = at(1).toString();
        assertRejected(Reason.EXPIRED, handle(strict, r.signed()));
        r.id = "_lr3";
        r.issueInstant = at(-300).toString();
        assertRejected(Reason.EXPIRED, handle(strict, r.signed()));
        r.id = "_lr4";
        r.issueInstant = at(-299).toString();
        assertEnded(handle(strict, r.signed()));
    }

    @Test
    public void testExpiredNotOnOrAfterIsRefused() {
        final ServiceProvider sp = sp(TestIdp.configWithLogout().clockDriftSeconds(120));
        final Request r = new Request("_lr1");
        r.notOnOrAfter = at(300).toString();
        assertEnded(handle(sp, r.signed()));
        r.id = "_lr2";
        r.notOnOrAfter = at(-119).toString();
        assertEnded(handle(sp, r.signed()));
        r.id = "_lr3";
        r.notOnOrAfter = at(-120).toString();
        assertRejected(Reason.EXPIRED, handle(sp, r.signed()));
        r.id = "_lr4";
        r.notOnOrAfter = at(-3600).toString();
        assertRejected(Reason.EXPIRED, handle(sp, r.signed()));
    }

    // ---- replay ----------------------------------------------------------------------------------------------------

    @Test
    public void testSameRequestIdIsRefusedTheSecondTime() {
        final ServiceProvider sp = sp();
        final String query = new Request("_lr1").signed();
        assertEnded(handle(sp, query));
        assertRejected(Reason.REPLAYED, handle(sp, query));
        // another ID is a different message
        assertEnded(handle(sp, new Request("_lr2").signed()));
    }

    @Test
    public void testReplayIsRefusedWhateverTheFirstOutcomeWas() {
        final ServiceProvider sp = sp();
        final Request other = new Request("_lr1").nameId("bob@example.com");
        assertKeptAndAnswered(handle(sp, other.signed()));
        assertRejected(Reason.REPLAYED, handle(sp, other.signed()));
        // the replay cache of another provider instance is separate
        assertKeptAndAnswered(handle(sp(), other.signed()));
    }

    @Test
    public void testSharedReplayCacheStopsReplayAcrossProviders() {
        final ReplayCache cache = new InMemoryReplayCache(100, TestIdp.CLOCK);
        final ServiceProvider a = ServiceProvider.create(TestIdp.configWithLogout().build(), cache);
        final ServiceProvider b = ServiceProvider.create(TestIdp.configWithLogout().build(), cache);
        final String query = new Request("_lr1").signed();
        assertEnded(handle(a, query));
        assertRejected(Reason.REPLAYED, handle(b, query));
    }

    // ---- LogoutResponse --------------------------------------------------------------------------------------------

    private static String responseQuery(final String id, final String status) {
        return LogoutTestSupport.redirectQuery("SAMLResponse", TestIdp.logoutResponseXml(id, status), null, TestIdp.IDP_KEY);
    }

    @Test
    public void testSuccessfulLogoutResponseKeepsTheSessionAndIsNotAnswered() {
        final ServiceProvider sp = sp();
        final LogoutOutcome o = handle(sp, responseQuery("_resp1", Names.STATUS_SUCCESS));
        assertEquals(Action.KEEP_SESSION, o.action(), o.toString());
        assertNull(o.redirectUrl());
        assertNull(o.reason());
        assertNotNull(o.detail());
    }

    @Test
    public void testLogoutResponseNeverEndsTheSession() {
        final ServiceProvider sp = sp();
        final String[] names = { USER, null, "bob@example.com" };
        final String[] indexes = { INDEX, null };
        int n = 0;
        for (final String name : names) {
            for (final String index : indexes) {
                // even a response that carries a NameID and a SessionIndex of this very session
                final String xml = TestIdp.logoutResponseXml("_resp" + n++, Names.STATUS_SUCCESS)
                        .replace("</saml:Issuer>", "</saml:Issuer><saml:NameID>" + USER + "</saml:NameID><samlp:SessionIndex>" + INDEX
                                + "</samlp:SessionIndex>");
                final LogoutOutcome o =
                        sp.handleLogout("GET", LogoutTestSupport.redirectQuery("SAMLResponse", xml, null, TestIdp.IDP_KEY), name, index);
                assertNotEquals(Action.END_SESSION, o.action(), o.toString());
                assertEquals(Action.KEEP_SESSION, o.action(), o.toString());
                assertNull(o.redirectUrl());
            }
        }
    }

    @Test
    public void testLogoutResponseWithFailureStatusIsRefused() {
        final ServiceProvider sp = sp();
        assertEquals(Action.KEEP_SESSION, handle(sp, responseQuery("_resp0", Names.STATUS_SUCCESS)).action());
        for (final String status : new String[] { "urn:oasis:names:tc:SAML:2.0:status:Responder",
                "urn:oasis:names:tc:SAML:2.0:status:Requester", "urn:oasis:names:tc:SAML:2.0:status:PartialLogout",
                Names.STATUS_SUCCESS + "x", "" }) {
            final LogoutOutcome o = handle(sp, responseQuery("_resp" + status.hashCode(), status));
            assertRejected(Reason.STATUS_NOT_SUCCESS, o);
        }
    }

    @Test
    public void testLogoutResponseWithoutStatusIsRefused() {
        final ServiceProvider sp = sp();
        assertEquals(Action.KEEP_SESSION, handle(sp, responseQuery("_resp0", Names.STATUS_SUCCESS)).action());
        final String xml = TestIdp.logoutResponseXml("_resp1", Names.STATUS_SUCCESS).replaceAll("<samlp:Status>.*</samlp:Status>", "");
        assertRejected(Reason.MALFORMED, handle(sp, LogoutTestSupport.redirectQuery("SAMLResponse", xml, null, TestIdp.IDP_KEY)));
    }

    @Test
    public void testLogoutResponseOutcomeOfTheSecondUseIsReplay() {
        final ServiceProvider sp = sp();
        final String query = responseQuery("_resp1", Names.STATUS_SUCCESS);
        assertEquals(Action.KEEP_SESSION, handle(sp, query).action());
        assertRejected(Reason.REPLAYED, handle(sp, query));
    }

    @Test
    public void testUnsignedLogoutResponseFollowsTheSignatureSetting() {
        final String unsigned =
                LogoutTestSupport.redirectQuery("SAMLResponse", TestIdp.logoutResponseXml("_resp1", Names.STATUS_SUCCESS), null, null);
        assertRejected(Reason.NOT_SIGNED, handle(sp(), unsigned));
        final LogoutOutcome o = handle(spAcceptingUnsigned(), unsigned);
        assertEquals(Action.KEEP_SESSION, o.action(), o.toString());
        // a bad signature is refused either way
        final String bad = LogoutTestSupport.redirectQuery("SAMLResponse", TestIdp.logoutResponseXml("_resp2", Names.STATUS_SUCCESS), null,
                TestIdp.OTHER_KEY);
        assertRejected(Reason.INVALID_SIGNATURE, handle(spAcceptingUnsigned(), bad));
        assertRejected(Reason.INVALID_SIGNATURE, handle(sp(), bad));
    }

    @Test
    public void testLogoutResponseIssuerAndDestinationAreChecked() {
        final ServiceProvider sp = sp();
        final String base = TestIdp.logoutResponseXml("_resp0", Names.STATUS_SUCCESS);
        assertEquals(Action.KEEP_SESSION,
                handle(sp, LogoutTestSupport.redirectQuery("SAMLResponse", base, null, TestIdp.IDP_KEY)).action());
        final String wrongIssuer =
                base.replace("_resp0", "_resp1").replace("<saml:Issuer>" + TestIdp.IDP, "<saml:Issuer>https://evil.example.com");
        assertRejected(Reason.WRONG_ISSUER,
                handle(sp, LogoutTestSupport.redirectQuery("SAMLResponse", wrongIssuer, null, TestIdp.IDP_KEY)));
        final String wrongDestination =
                base.replace("_resp0", "_resp2").replace("Destination=\"" + TestIdp.SLS, "Destination=\"" + TestIdp.ACS);
        assertRejected(Reason.WRONG_DESTINATION,
                handle(sp, LogoutTestSupport.redirectQuery("SAMLResponse", wrongDestination, null, TestIdp.IDP_KEY)));
    }

    @Test
    public void testLogoutResponseWithTheWrongRootIsRefused() {
        final ServiceProvider sp = sp();
        final String request = new Request("_lr1").xml();
        assertRejected(Reason.MALFORMED, handle(sp, LogoutTestSupport.redirectQuery("SAMLResponse", request, null, TestIdp.IDP_KEY)));
    }

    @Test
    public void testLogoutResponseDoesNotEchoRelayState() {
        final ServiceProvider sp = sp();
        final String query = LogoutTestSupport.redirectQuery("SAMLResponse", TestIdp.logoutResponseXml("_resp1", Names.STATUS_SUCCESS),
                "state", TestIdp.IDP_KEY);
        final LogoutOutcome o = handle(sp, query);
        assertEquals(Action.KEEP_SESSION, o.action(), o.toString());
        assertNull(o.redirectUrl());
    }

    // ---- RelayState ------------------------------------------------------------------------------------------------

    @Test
    public void testRelayStateIsEchoedAndCoveredByTheAnswerSignature() {
        final String relay = "https://fess.example.com/app?x=1&y=2 é/+";
        final LogoutOutcome o = handle(sp(), new Request("_lr1").signed(relay));
        assertEnded(o);
        final Sent answer = sent(o.redirectUrl());
        assertEquals(relay, answer.param("RelayState"));
        assertTrue(answer.signatureVerifies(TestIdp.SP_CERT));
        assertTrue(answer.signedString().contains("&RelayState=" + answer.raw.get("RelayState") + "&SigAlg="));
    }

    @Test
    public void testRelayStateIsEchoedOnAnAnswerThatKeepsTheSession() {
        final LogoutOutcome o = handle(sp(), new Request("_lr1").nameId("bob@example.com").signed("back"));
        assertKeptAndAnswered(o);
        assertEquals("back", sent(o.redirectUrl()).param("RelayState"));
    }

    @Test
    public void testRelayStateOfAtMost512CharactersIsEchoed() {
        final ServiceProvider sp = sp();
        final String atLimit = "a".repeat(512);
        final LogoutOutcome ok = handle(sp, new Request("_lr1").signed(atLimit));
        assertEnded(ok);
        assertEquals(atLimit, sent(ok.redirectUrl()).param("RelayState"));

        final LogoutOutcome longer = handle(sp, new Request("_lr2").signed("a".repeat(513)));
        assertEnded(longer);
        assertFalse(sent(longer.redirectUrl()).raw.containsKey("RelayState"));
        assertTrue(sent(longer.redirectUrl()).signatureVerifies(TestIdp.SP_CERT));
    }

    @Test
    public void testAbsentOrEmptyRelayStateIsNotSent() {
        final ServiceProvider sp = sp();
        assertFalse(sent(handle(sp, new Request("_lr1").signed()).redirectUrl()).raw.containsKey("RelayState"));
        assertFalse(sent(handle(sp, new Request("_lr2").signed("")).redirectUrl()).raw.containsKey("RelayState"));
    }

    // ---- details that reach a log ----------------------------------------------------------------------------------

    @Test
    public void testDetailNeverContainsLineBreaksFromTheIssuer() {
        final ServiceProvider sp = sp();
        control(sp);
        int n = 0;
        for (final String bad : new String[] { "evil\r\nINJECTED line", "evil\nINJECTED", "evil\rX", "evil\u0085X", "evil X", "evil X",
                "evil\tX" }) {
            final Request r = new Request("_i" + n++);
            r.issuer = bad;
            final LogoutOutcome o = handle(sp, r.signed());
            assertRejected(Reason.WRONG_ISSUER, o);
            assertFalse(LINE_BREAK.matcher(o.detail()).find(), "detail for issuer " + n + ": " + o.detail());
            assertFalse(ANY_CONTROL.matcher(o.detail()).find(), "detail for issuer " + n + ": " + o.detail());
        }
    }

    @Test
    public void testDetailNeverContainsLineBreaksFromTheDestination() {
        final ServiceProvider sp = sp();
        control(sp);
        int n = 0;
        for (final String bad : new String[] { "https://x.example.com/\r\nINJECTED line", "a\nb", "a\u0085b", "a b" }) {
            final Request r = new Request("_d" + n++);
            r.destination = bad;
            final LogoutOutcome o = handle(sp, r.signed());
            assertRejected(Reason.WRONG_DESTINATION, o);
            assertFalse(ANY_CONTROL.matcher(o.detail()).find(), o.detail());
        }
    }

    @Test
    public void testDetailNeverContainsLineBreaksFromTheStatus() {
        final ServiceProvider sp = sp();
        final String status = "urn:x\r\nINJECTED";
        final LogoutOutcome o = handle(sp, responseQuery("_resp1", status));
        assertRejected(Reason.STATUS_NOT_SUCCESS, o);
        assertFalse(ANY_CONTROL.matcher(o.detail()).find(), o.detail());
    }

    @Test
    public void testDetailFromAMessageIsBounded() {
        final ServiceProvider sp = sp();
        final Request r = new Request("_lr1");
        r.issuer = "x".repeat(50_000);
        final LogoutOutcome o = handle(sp, r.signed());
        assertRejected(Reason.WRONG_ISSUER, o);
        assertTrue(o.detail().length() < 400, "detail length " + o.detail().length());
    }
}
