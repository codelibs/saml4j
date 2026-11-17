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
import static org.codelibs.saml4j.ResponseTestSupport.addAttribute;
import static org.codelibs.saml4j.ResponseTestSupport.assertion;
import static org.codelibs.saml4j.ResponseTestSupport.child;
import static org.codelibs.saml4j.ResponseTestSupport.configWithKey;
import static org.codelibs.saml4j.ResponseTestSupport.controlAndChange;
import static org.codelibs.saml4j.ResponseTestSupport.element;
import static org.codelibs.saml4j.ResponseTestSupport.first;
import static org.codelibs.saml4j.ResponseTestSupport.login;
import static org.codelibs.saml4j.ResponseTestSupport.refused;
import static org.codelibs.saml4j.ResponseTestSupport.response;
import static org.codelibs.saml4j.ResponseTestSupport.signAssertion;
import static org.codelibs.saml4j.ResponseTestSupport.signResponse;
import static org.codelibs.saml4j.ResponseTestSupport.signatureOf;
import static org.codelibs.saml4j.ResponseTestSupport.signedResponse;
import static org.codelibs.saml4j.ResponseTestSupport.unsigned;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;

import org.codelibs.saml4j.internal.Names;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Ordinary validation of a login response: every reason a response is refused, each next to the same response being
 * accepted without the problem.
 */
public class LoginTest {

    private static final Instant NOW = TestIdp.NOW;

    // ---- helpers ---------------------------------------------------------------------------------------------------

    private static String encoded(final Consumer<TestIdp.ResponseSpec> change) {
        final TestIdp.ResponseSpec spec = TestIdp.response();
        change.accept(spec);
        return spec.encoded();
    }

    /** A response document without signatures; the caller signs it after changing it. */
    private static Document draft() {
        return unsigned(TestIdp.response());
    }

    private static Element subject(final Document doc) {
        return child(assertion(doc), Names.NS_SAML, "Subject");
    }

    private static Element confirmationData(final Document doc) {
        return child(child(subject(doc), Names.NS_SAML, "SubjectConfirmation"), Names.NS_SAML, "SubjectConfirmationData");
    }

    private static Element conditions(final Document doc) {
        return child(assertion(doc), Names.NS_SAML, "Conditions");
    }

    private static Element nameId(final Document doc) {
        return child(subject(doc), Names.NS_SAML, "NameID");
    }

    // ---- the accepted response -------------------------------------------------------------------------------------

    @Test
    public void testSignedResponseIsAcceptedWithAllItsParts() {
        final TestIdp.ResponseSpec spec = TestIdp.response();
        spec.sessionNotOnOrAfter = NOW.plusSeconds(3600);
        final LoginResult.Authenticated a = accepted(login(spec.encoded()));
        assertEquals("alice@example.com", a.nameId().value());
        assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", a.nameId().format());
        assertNull(a.nameId().nameQualifier());
        assertEquals("_session1", a.sessionIndex());
        assertEquals(NOW.plusSeconds(3600), a.sessionNotOnOrAfter());
        assertEquals("_req1", a.requestId());
        assertEquals(List.of("staff", "dev"), a.attributes().get("memberOf"));
    }

    @Test
    public void testNameQualifiersAreReported() {
        final Document doc = draft();
        nameId(doc).setAttribute("NameQualifier", "https://idp.example.com/metadata");
        nameId(doc).setAttribute("SPNameQualifier", TestIdp.SP);
        final LoginResult.Authenticated a = accepted(login(signedResponse(doc)));
        assertEquals("https://idp.example.com/metadata", a.nameId().nameQualifier());
        assertEquals(TestIdp.SP, a.nameId().spNameQualifier());
    }

    // ---- audience --------------------------------------------------------------------------------------------------

    @Test
    public void testWrongAudienceIsRefused() {
        controlAndChange(Reason.WRONG_AUDIENCE,
                attack -> encoded(s -> s.audience = attack ? "https://other.example.com/metadata" : TestIdp.SP));
    }

    @Test
    public void testAudienceThatOnlyLooksLikeTheServiceProviderIsRefused() {
        accepted(login(encoded(s -> s.audience = TestIdp.SP)));
        for (final String audience : new String[] { TestIdp.SP + "/", TestIdp.SP + "x", TestIdp.SP.toUpperCase(), "x" + TestIdp.SP,
                "https://fess.example.com/sso", "" }) {
            refused(Reason.WRONG_AUDIENCE, login(encoded(s -> s.audience = audience)));
        }
    }

    @Test
    public void testMissingAudienceRestrictionIsRefused() {
        controlAndChange(Reason.WRONG_AUDIENCE, attack -> {
            final Document doc = draft();
            if (attack) {
                conditions(doc).removeChild(child(conditions(doc), Names.NS_SAML, "AudienceRestriction"));
            }
            return signedResponse(doc);
        });
    }

    @Test
    public void testSecondRestrictionThatDoesNotNameTheServiceProviderIsRefused() {
        controlAndChange(Reason.WRONG_AUDIENCE, attack -> {
            final Document doc = draft();
            final Element second = element(doc, Names.NS_SAML, "saml:AudienceRestriction");
            final Element audience = element(doc, Names.NS_SAML, "saml:Audience");
            audience.setTextContent(attack ? "https://other.example.com/metadata" : TestIdp.SP);
            second.appendChild(audience);
            conditions(doc).appendChild(second);
            return signedResponse(doc);
        });
    }

    @Test
    public void testFirstRestrictionThatDoesNotNameTheServiceProviderIsRefused() {
        controlAndChange(Reason.WRONG_AUDIENCE, attack -> {
            final Document doc = draft();
            final Element first = element(doc, Names.NS_SAML, "saml:AudienceRestriction");
            final Element audience = element(doc, Names.NS_SAML, "saml:Audience");
            audience.setTextContent(attack ? "https://other.example.com/metadata" : TestIdp.SP);
            first.appendChild(audience);
            conditions(doc).insertBefore(first, conditions(doc).getFirstChild());
            return signedResponse(doc);
        });
    }

    @Test
    public void testRestrictionWithSeveralAudiencesNeedsOnlyOneToNameTheServiceProvider() {
        final Document doc = draft();
        final Element restriction = child(conditions(doc), Names.NS_SAML, "AudienceRestriction");
        final Element other = element(doc, Names.NS_SAML, "saml:Audience");
        other.setTextContent("https://other.example.com/metadata");
        restriction.insertBefore(other, restriction.getFirstChild());
        accepted(login(signedResponse(doc)));
    }

    @Test
    public void testUnknownConditionIsRefused() {
        controlAndChange(Reason.UNSUPPORTED, attack -> {
            final Document doc = draft();
            conditions(doc).appendChild(element(doc, Names.NS_SAML, attack ? "saml:Condition" : "saml:OneTimeUse"));
            return signedResponse(doc);
        });
    }

    @Test
    public void testXmlIdEqualToTheIdOfTheSignedElementIsRefused() {
        controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = draft();
            final org.w3c.dom.Element issuer = child(assertion(doc), Names.NS_SAML, "Issuer");
            issuer.setAttributeNS("http://www.w3.org/XML/1998/namespace", "xml:id", attack ? response(doc).getAttribute("ID") : "_other");
            return signedResponse(doc);
        });
    }

    @Test
    public void testAssertionIssuedInTheFutureBeyondTheDriftIsRefused() {
        controlAndChange(Reason.EXPIRED, attack -> {
            final Document doc = draft();
            assertion(doc).setAttribute("IssueInstant", NOW.plusSeconds(attack ? 121 : 120).toString());
            return signedResponse(doc);
        });
    }

    // ---- recipient and destination ---------------------------------------------------------------------------------

    @Test
    public void testWrongRecipientIsReportedAsWrongDestination() {
        controlAndChange(Reason.WRONG_DESTINATION,
                attack -> encoded(s -> s.recipient = attack ? "https://other.example.com/sso/" : TestIdp.ACS));
    }

    @Test
    public void testWrongDestinationIsRefused() {
        controlAndChange(Reason.WRONG_DESTINATION,
                attack -> encoded(s -> s.destination = attack ? "https://other.example.com/sso/" : TestIdp.ACS));
    }

    @Test
    public void testDestinationThatDiffersOnlyInTheLastCharacterIsRefused() {
        accepted(login(encoded(s -> s.destination = TestIdp.ACS)));
        for (final String destination : new String[] { "https://fess.example.com/sso", "http://fess.example.com/sso/",
                "https://fess.example.com/sso/?x=1", "https://FESS.example.com/sso/", "" }) {
            refused(Reason.WRONG_DESTINATION, login(encoded(s -> s.destination = destination)));
        }
    }

    @Test
    public void testSignedResponseWithoutDestinationIsRefused() {
        controlAndChange(Reason.WRONG_DESTINATION, attack -> {
            final Document doc = draft();
            if (attack) {
                response(doc).removeAttribute("Destination");
            }
            return signedResponse(doc);
        });
    }

    // ---- issuer ----------------------------------------------------------------------------------------------------

    @Test
    public void testWrongIssuerOnTheAssertionIsRefused() {
        controlAndChange(Reason.WRONG_ISSUER, attack -> {
            final Document doc = draft();
            if (attack) {
                child(assertion(doc), Names.NS_SAML, "Issuer").setTextContent("https://evil.example.com/metadata");
            }
            return signedResponse(doc);
        });
    }

    @Test
    public void testWrongIssuerOnTheResponseIsRefused() {
        controlAndChange(Reason.WRONG_ISSUER, attack -> {
            final Document doc = draft();
            if (attack) {
                child(response(doc), Names.NS_SAML, "Issuer").setTextContent("https://evil.example.com/metadata");
            }
            return signedResponse(doc);
        });
    }

    @Test
    public void testIssuerThatOnlyLooksLikeTheIdentityProviderIsRefused() {
        accepted(login(encoded(s -> s.issuer = TestIdp.IDP)));
        for (final String issuer : new String[] { TestIdp.IDP + "/", TestIdp.IDP + "x", TestIdp.IDP.toUpperCase() }) {
            refused(Reason.WRONG_ISSUER, login(encoded(s -> s.issuer = issuer)));
        }
    }

    @Test
    public void testMissingIssuerOnTheAssertionIsRefused() {
        controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = draft();
            if (attack) {
                final Element issuer = child(assertion(doc), Names.NS_SAML, "Issuer");
                assertion(doc).removeChild(issuer);
            }
            return signedResponse(doc);
        });
    }

    @Test
    public void testResponseWithoutIssuerIsAcceptedWhenTheAssertionNamesTheProvider() {
        final Document doc = draft();
        response(doc).removeChild(child(response(doc), Names.NS_SAML, "Issuer"));
        accepted(login(signedResponse(doc)));
    }

    @Test
    public void testIssuerWithAChildElementIsRefused() {
        controlAndChange(Reason.WRONG_ISSUER, attack -> {
            final Document doc = draft();
            if (attack) {
                child(assertion(doc), Names.NS_SAML, "Issuer").appendChild(element(doc, Names.NS_SAML, "saml:Extra"));
            }
            return signedResponse(doc);
        });
    }

    // ---- time ------------------------------------------------------------------------------------------------------

    @Test
    public void testConditionsNotOnOrAfterInsideTheDriftIsAcceptedAndOutsideIsRefused() {
        controlAndChange(Reason.EXPIRED, attack -> encoded(s -> {
            s.notBefore = NOW.minusSeconds(600);
            s.notOnOrAfter = NOW.minusSeconds(attack ? 120 : 119);
        }));
    }

    @Test
    public void testConditionsNotBeforeInsideTheDriftIsAcceptedAndOutsideIsRefused() {
        controlAndChange(Reason.EXPIRED, attack -> encoded(s -> s.notBefore = NOW.plusSeconds(attack ? 121 : 120)));
    }

    @Test
    public void testSessionNotOnOrAfterInsideTheDriftIsAcceptedAndOutsideIsRefused() {
        controlAndChange(Reason.EXPIRED, attack -> encoded(s -> s.sessionNotOnOrAfter = NOW.minusSeconds(attack ? 120 : 119)));
    }

    @Test
    public void testSessionNotOnOrAfterInTheFutureIsReported() {
        final LoginResult.Authenticated a = accepted(login(encoded(s -> s.sessionNotOnOrAfter = NOW.plusSeconds(28800))));
        assertEquals(NOW.plusSeconds(28800), a.sessionNotOnOrAfter());
    }

    @Test
    public void testConfirmationNotOnOrAfterOutsideTheDriftIsReportedAsExpired() {
        controlAndChange(Reason.EXPIRED, attack -> encoded(s -> s.confirmationNotOnOrAfter = NOW.minusSeconds(attack ? 120 : 119)));
    }

    @Test
    public void testConfirmationNotBeforeOutsideTheDriftIsReportedAsExpired() {
        controlAndChange(Reason.EXPIRED, attack -> {
            final Document doc = draft();
            confirmationData(doc).setAttribute("NotBefore", NOW.plusSeconds(attack ? 121 : 120).toString());
            return signedResponse(doc);
        });
    }

    @Test
    public void testConfirmationWithoutNotOnOrAfterIsRefused() {
        controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = draft();
            if (attack) {
                confirmationData(doc).removeAttribute("NotOnOrAfter");
            }
            return signedResponse(doc);
        });
    }

    @Test
    public void testTimeValueThatIsNotADateTimeIsRefused() {
        controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = draft();
            conditions(doc).setAttribute("NotOnOrAfter", attack ? "tomorrow" : NOW.plusSeconds(300).toString());
            return signedResponse(doc);
        });
    }

    @Test
    public void testClockDriftIsConfigurable() {
        final String atTheEdge = encoded(s -> s.notOnOrAfter = NOW);
        // NotOnOrAfter equal to now is already over when there is no drift
        refused(Reason.EXPIRED, login(TestIdp.config().clockDriftSeconds(0), atTheEdge));
        accepted(login(TestIdp.config().clockDriftSeconds(1), atTheEdge));
        final String longAgo = encoded(s -> {
            s.notBefore = NOW.minusSeconds(900);
            s.notOnOrAfter = NOW.minusSeconds(300);
        });
        refused(Reason.EXPIRED, login(TestIdp.config(), longAgo));
        accepted(login(TestIdp.config().clockDriftSeconds(301), longAgo));
    }

    // ---- request ID ------------------------------------------------------------------------------------------------

    @Test
    public void testResponseToARequestThatIsNotPendingIsRefused() {
        final String message = TestIdp.response().encoded();
        accepted(login(message));
        final LoginResult r = ServiceProvider.create(TestIdp.config().build()).finishLogin(message, Set.of("_other"));
        refused(Reason.WRONG_IN_RESPONSE_TO, r);
    }

    @Test
    public void testEmptyOrMissingPendingSetIsRefused() {
        final String message = TestIdp.response().encoded();
        accepted(login(message));
        refused(Reason.WRONG_IN_RESPONSE_TO, ServiceProvider.create(TestIdp.config().build()).finishLogin(message, Set.of()));
        refused(Reason.WRONG_IN_RESPONSE_TO, ServiceProvider.create(TestIdp.config().build()).finishLogin(message, null));
    }

    @Test
    public void testResponseAnsweringAnotherPendingRequestThanTheAssertionIsRefused() {
        final Set<String> both = Set.of("_req1", "_req2");
        final String control = TestIdp.response().encoded();
        accepted(ServiceProvider.create(TestIdp.config().build()).finishLogin(control, both));

        final Document doc = draft();
        response(doc).setAttribute("InResponseTo", "_req2");
        final LoginResult r = ServiceProvider.create(TestIdp.config().build()).finishLogin(signedResponse(doc), both);
        refused(Reason.WRONG_IN_RESPONSE_TO, r);
    }

    @Test
    public void testAssertionConfirmationForAnotherRequestIsRefusedWhenTheResponseIsUnsolicited() {
        final Set<String> pending = Set.of("_req1");
        final Document doc = draft();
        response(doc).removeAttribute("InResponseTo");
        final String control = signedResponse(doc);
        accepted(ServiceProvider.create(TestIdp.config().build()).finishLogin(control, pending));

        final TestIdp.ResponseSpec spec = TestIdp.response();
        spec.requestId = "_unknown";
        final Document other = unsigned(spec);
        response(other).removeAttribute("InResponseTo");
        refused(Reason.WRONG_IN_RESPONSE_TO, ServiceProvider.create(TestIdp.config().build()).finishLogin(signedResponse(other), pending));
    }

    @Test
    public void testRequestIdReportedIsTheOneTheResponseAnswered() {
        final TestIdp.ResponseSpec spec = TestIdp.response();
        spec.requestId = "_req2";
        final LoginResult r = ServiceProvider.create(TestIdp.config().build()).finishLogin(spec.encoded(), Set.of("_req1", "_req2"));
        assertEquals("_req2", accepted(r).requestId());
    }

    @Test
    public void testConfirmationWithoutInResponseToIsRefused() {
        controlAndChange(Reason.WRONG_IN_RESPONSE_TO, attack -> {
            final Document doc = draft();
            if (attack) {
                confirmationData(doc).removeAttribute("InResponseTo");
            }
            return signedResponse(doc);
        });
    }

    @Test
    public void testSecondConfirmationIsUsedWhenTheFirstDoesNotMatch() {
        final Document doc = draft();
        final Element first = child(subject(doc), Names.NS_SAML, "SubjectConfirmation");
        final Element wrong = (Element) first.cloneNode(true);
        child(wrong, Names.NS_SAML, "SubjectConfirmationData").setAttribute("Recipient", "https://other.example.com/sso/");
        subject(doc).insertBefore(wrong, first);
        accepted(login(signedResponse(doc)));
    }

    @Test
    public void testConfirmationMethodOtherThanBearerIsNotUsed() {
        controlAndChange(Reason.WRONG_IN_RESPONSE_TO, attack -> {
            final Document doc = draft();
            final Element sc = child(subject(doc), Names.NS_SAML, "SubjectConfirmation");
            sc.setAttribute("Method", attack ? "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key" : Names.CM_BEARER);
            return signedResponse(doc);
        });
    }

    // ---- status ----------------------------------------------------------------------------------------------------

    @Test
    public void testStatusThatIsNotSuccessIsRefused() {
        controlAndChange(Reason.STATUS_NOT_SUCCESS,
                attack -> encoded(s -> s.status = attack ? "urn:oasis:names:tc:SAML:2.0:status:Responder" : Names.STATUS_SUCCESS));
    }

    @Test
    public void testFailureStatusIsReportedEvenWhenTheResponseIsNotSigned() {
        accepted(login(TestIdp.response().encoded()));
        final TestIdp.ResponseSpec spec = TestIdp.response();
        spec.status = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        spec.signResponse = false;
        refused(Reason.STATUS_NOT_SUCCESS, login(spec.encoded()));
        // the same unsigned response with a success status is refused for the missing signature instead
        spec.status = Names.STATUS_SUCCESS;
        refused(Reason.NOT_SIGNED, login(spec.encoded()));
    }

    // ---- replay ----------------------------------------------------------------------------------------------------

    @Test
    public void testSameResponseTwiceOnTheSameServiceProviderIsReplayed() {
        final String message = TestIdp.response().encoded();
        final ServiceProvider sp = ServiceProvider.create(TestIdp.config().build());
        accepted(sp.finishLogin(message, PENDING));
        refused(Reason.REPLAYED, sp.finishLogin(message, PENDING));
        refused(Reason.REPLAYED, sp.finishLogin(message, PENDING));
    }

    @Test
    public void testSameResponseOnAServiceProviderWithAFreshCacheIsAccepted() {
        final String message = TestIdp.response().encoded();
        accepted(ServiceProvider.create(TestIdp.config().build()).finishLogin(message, PENDING));
        accepted(ServiceProvider.create(TestIdp.config().build()).finishLogin(message, PENDING));
    }

    @Test
    public void testServiceProvidersSharingACacheRefuseTheSameResponse() {
        final String message = TestIdp.response().encoded();
        final ReplayCache cache = new InMemoryReplayCache(100, TestIdp.CLOCK);
        accepted(ServiceProvider.create(TestIdp.config().build(), cache).finishLogin(message, PENDING));
        refused(Reason.REPLAYED, ServiceProvider.create(TestIdp.config().build(), cache).finishLogin(message, PENDING));
    }

    @Test
    public void testSameAssertionInAnotherResponseIsReplayed() {
        final TestIdp.ResponseSpec spec = TestIdp.response();
        spec.signResponse = false;
        spec.signAssertion = true;
        final String first = spec.encoded();
        spec.responseId = "_another_response";
        final String second = spec.encoded();
        final ServiceProvider sp = ServiceProvider.create(TestIdp.config().build());
        accepted(sp.finishLogin(first, PENDING));
        refused(Reason.REPLAYED, sp.finishLogin(second, PENDING));
    }

    @Test
    public void testRefusedResponseIsNotRememberedAsUsed() {
        final ServiceProvider sp = ServiceProvider.create(TestIdp.config().build());
        final TestIdp.ResponseSpec spec = TestIdp.response();
        final Document doc = unsigned(spec);
        final String unsignedMessage = TestIdp.encode(doc);
        refused(Reason.NOT_SIGNED, sp.finishLogin(unsignedMessage, PENDING));
        signResponse(doc);
        accepted(sp.finishLogin(TestIdp.encode(doc), PENDING));
    }

    // ---- signatures ------------------------------------------------------------------------------------------------

    @Test
    public void testSignatureByAnotherKeyIsRefused() {
        controlAndChange(Reason.INVALID_SIGNATURE, attack -> encoded(s -> s.signKey = attack ? TestIdp.OTHER_KEY : TestIdp.IDP_KEY));
    }

    @Test
    public void testAssertionSignatureByAnotherKeyIsRefused() {
        controlAndChange(Reason.INVALID_SIGNATURE, attack -> encoded(s -> {
            s.signResponse = false;
            s.signAssertion = true;
            s.signKey = attack ? TestIdp.OTHER_KEY : TestIdp.IDP_KEY;
        }));
    }

    @Test
    public void testAnyConfiguredCertificateMayVerify() {
        final String message = TestIdp.response().encoded();
        accepted(login(TestIdp.config().addIdpCertificate(TestIdp.OTHER_CERT), message));
        final String byOther = encoded(s -> s.signKey = TestIdp.OTHER_KEY);
        accepted(login(TestIdp.config().addIdpCertificate(TestIdp.OTHER_CERT), byOther));
        refused(Reason.INVALID_SIGNATURE, login(TestIdp.config(), byOther));
    }

    @Test
    public void testContentChangedAfterSigningTheResponseIsRefused() {
        final Document doc = TestIdp.response().document();
        accepted(login(TestIdp.encode(doc)));
        nameId(doc).setTextContent("admin@example.com");
        refused(Reason.INVALID_SIGNATURE, login(TestIdp.encode(doc)));
    }

    @Test
    public void testContentChangedAfterSigningTheAssertionIsRefused() {
        final TestIdp.ResponseSpec spec = TestIdp.response();
        spec.signResponse = false;
        spec.signAssertion = true;
        final Document doc = spec.document();
        accepted(login(TestIdp.encode(doc)));
        nameId(doc).setTextContent("admin@example.com");
        refused(Reason.INVALID_SIGNATURE, login(TestIdp.encode(doc)));
    }

    @Test
    public void testConditionsChangedAfterSigningAreRefused() {
        controlAndChange(Reason.INVALID_SIGNATURE, attack -> {
            final Document doc = TestIdp.response().document();
            if (attack) {
                conditions(doc).setAttribute("NotOnOrAfter", NOW.plusSeconds(86400).toString());
            }
            return TestIdp.encode(doc);
        });
    }

    @Test
    public void testSignatureValueChangedIsRefused() {
        final Document doc = TestIdp.response().document();
        accepted(login(TestIdp.encode(doc)));
        final Element value = child(signatureOf(response(doc)), Names.NS_DS, "SignatureValue");
        final String text = value.getTextContent();
        value.setTextContent((text.charAt(0) == 'A' ? "B" : "A") + text.substring(1));
        refused(Reason.INVALID_SIGNATURE, login(TestIdp.encode(doc)));
    }

    @Test
    public void testDigestValueChangedIsRefused() {
        final Document doc = TestIdp.response().document();
        accepted(login(TestIdp.encode(doc)));
        final Element value = first(doc, Names.NS_DS, "DigestValue");
        final String text = value.getTextContent();
        value.setTextContent((text.charAt(0) == 'A' ? "B" : "A") + text.substring(1));
        refused(Reason.INVALID_SIGNATURE, login(TestIdp.encode(doc)));
    }

    @Test
    public void testMessageWithNoSignatureAnywhereIsRefused() {
        controlAndChange(Reason.NOT_SIGNED, attack -> encoded(s -> s.signResponse = !attack));
    }

    // ---- wantMessagesSigned / wantAssertionsSigned / wantAssertionsEncrypted ---------------------------------------

    @Test
    public void testWantMessagesSignedRefusesAResponseThatOnlyTheAssertionIsSignedIn() {
        final SamlConfig.Builder config = TestIdp.config().wantMessagesSigned(true);
        controlAndChange(config, Reason.NOT_SIGNED, attack -> encoded(s -> {
            s.signResponse = !attack;
            s.signAssertion = attack;
        }));
    }

    @Test
    public void testWithoutWantMessagesSignedASignedAssertionIsEnough() {
        accepted(login(encoded(s -> {
            s.signResponse = false;
            s.signAssertion = true;
        })));
    }

    @Test
    public void testWantAssertionsSignedRefusesAnAssertionThatOnlyTheResponseCovers() {
        final SamlConfig.Builder config = TestIdp.config().wantAssertionsSigned(true);
        controlAndChange(config, Reason.NOT_SIGNED, attack -> encoded(s -> {
            s.signResponse = true;
            s.signAssertion = !attack;
        }));
    }

    @Test
    public void testWantBothAcceptsOnlyAResponseWithBothSignatures() {
        final SamlConfig.Builder config = TestIdp.config().wantMessagesSigned(true).wantAssertionsSigned(true);
        accepted(login(config, encoded(s -> {
            s.signResponse = true;
            s.signAssertion = true;
        })));
        refused(Reason.NOT_SIGNED, login(config, encoded(s -> {
            s.signResponse = true;
            s.signAssertion = false;
        })));
        refused(Reason.NOT_SIGNED, login(config, encoded(s -> {
            s.signResponse = false;
            s.signAssertion = true;
        })));
    }

    @Test
    public void testWantAssertionsEncryptedRefusesAPlainAssertion() {
        final SamlConfig.Builder config = configWithKey().wantAssertionsEncrypted(true);
        // the reason for "required but not encrypted" is UNSUPPORTED
        controlAndChange(config, Reason.UNSUPPORTED, attack -> encoded(s -> s.encryption = attack ? null : "cbc"));
    }

    @Test
    public void testEncryptedAssertionIsAcceptedWhenNotRequired() {
        final TestIdp.ResponseSpec spec = TestIdp.response();
        spec.encryption = "gcm";
        accepted(login(configWithKey(), spec.encoded()));
    }

    @Test
    public void testSignedEncryptedAssertionSatisfiesWantAssertionsSigned() {
        final SamlConfig.Builder config = configWithKey().wantAssertionsEncrypted(true).wantAssertionsSigned(true).wantMessagesSigned(true);
        controlAndChange(config, Reason.NOT_SIGNED, attack -> encoded(s -> {
            s.encryption = "cbc";
            s.signAssertion = !attack;
        }));
    }

    @Test
    public void testEncryptedAssertionWithoutAConfiguredKeyIsRefused() {
        final String message = encoded(s -> s.encryption = "cbc");
        accepted(login(configWithKey(), message));
        refused(Reason.DECRYPTION_FAILED, login(TestIdp.config(), message));
    }

    // ---- deprecated algorithms -------------------------------------------------------------------------------------

    @Test
    public void testSha1SignatureIsRefusedByDefaultAndAcceptedWhenAllowed() {
        final String message = encoded(s -> {
            s.sigAlg = Names.RSA_SHA1;
            s.digestAlg = Names.SHA1;
        });
        refused(Reason.INVALID_SIGNATURE, login(message));
        accepted(login(TestIdp.config().allowDeprecatedAlg(true), message));
        accepted(login(encoded(s -> {})));
    }

    @Test
    public void testSha1SignatureMethodAloneIsRefusedByDefault() {
        final String message = encoded(s -> s.sigAlg = Names.RSA_SHA1);
        refused(Reason.INVALID_SIGNATURE, login(message));
        accepted(login(TestIdp.config().allowDeprecatedAlg(true), message));
    }

    @Test
    public void testSha1DigestAloneIsRefusedByDefault() {
        final String message = encoded(s -> s.digestAlg = Names.SHA1);
        refused(Reason.INVALID_SIGNATURE, login(message));
        accepted(login(TestIdp.config().allowDeprecatedAlg(true), message));
    }

    @Test
    public void testSha1OnAnAssertionSignatureIsRefusedByDefault() {
        final String message = encoded(s -> {
            s.signResponse = false;
            s.signAssertion = true;
            s.sigAlg = Names.RSA_SHA1;
            s.digestAlg = Names.SHA1;
        });
        refused(Reason.INVALID_SIGNATURE, login(message));
        accepted(login(TestIdp.config().allowDeprecatedAlg(true), message));
    }

    @Test
    public void testStrongerSignatureAlgorithmsAreAccepted() {
        for (final String alg : new String[] { Names.RSA_SHA384, Names.RSA_SHA512 }) {
            accepted(login(encoded(s -> s.sigAlg = alg)));
        }
        accepted(login(encoded(s -> s.digestAlg = "http://www.w3.org/2001/04/xmlenc#sha512")));
    }

    @Test
    public void testRsa15KeyTransportIsRefusedByDefaultAndAcceptedWhenAllowed() {
        final String message = encoded(s -> {
            s.encryption = "cbc";
            s.keyTransport = "rsa15";
        });
        refused(Reason.DECRYPTION_FAILED, login(configWithKey(), message));
        accepted(login(configWithKey().allowRsa15(true), message));
        accepted(login(configWithKey(), encoded(s -> s.encryption = "cbc")));
    }

    @Test
    public void testAllowingRsa15StillAcceptsOaep() {
        accepted(login(configWithKey().allowRsa15(true), encoded(s -> s.encryption = "gcm")));
    }

    // ---- attributes ------------------------------------------------------------------------------------------------

    @Test
    public void testAttributeThatAppearsTwiceIsMerged() {
        final Document doc = draft();
        addAttribute(doc, "memberOf", "admin");
        addAttribute(doc, "mail", "alice@example.com");
        addAttribute(doc, "mail", "alice@corp.example.com", "a@example.com");
        final LoginResult.Authenticated a = accepted(login(signedResponse(doc)));
        assertEquals(List.of("staff", "dev", "admin"), a.attributes().get("memberOf"));
        assertEquals(List.of("alice@example.com", "alice@corp.example.com", "a@example.com"), a.attributes().get("mail"));
        assertEquals(List.of("memberOf", "mail"), List.copyOf(a.attributes().keySet()));
    }

    @Test
    public void testAttributeSplitOverTwoStatementsIsMerged() {
        final Document doc = draft();
        final Element statement = first(doc, Names.NS_SAML, "AttributeStatement");
        final Element second = (Element) statement.cloneNode(true);
        assertion(doc).appendChild(second);
        final LoginResult.Authenticated a = accepted(login(signedResponse(doc)));
        assertEquals(List.of("staff", "dev", "staff", "dev"), a.attributes().get("memberOf"));
    }

    @Test
    public void testAttributeValueWithAChildElementIsSkipped() {
        final Document doc = draft();
        addAttribute(doc, "tag", "one", "two", "three");
        final Element two = TestIdp.all(doc, Names.NS_SAML, "AttributeValue").get(3);
        assertEquals("two", two.getTextContent());
        two.setTextContent("");
        final Element nested = element(doc, Names.NS_SAML, "saml:NameID");
        nested.setTextContent("evil");
        two.appendChild(nested);
        final LoginResult.Authenticated a = accepted(login(signedResponse(doc)));
        assertEquals(List.of("one", "three"), a.attributes().get("tag"));
    }

    @Test
    public void testAttributeValueMixingTextAndAChildElementIsSkippedAsAWhole() {
        final Document doc = draft();
        addAttribute(doc, "role", "admin");
        final Element value = TestIdp.all(doc, Names.NS_SAML, "AttributeValue").get(2);
        value.appendChild(element(doc, Names.NS_SAML, "saml:Extra"));
        final LoginResult.Authenticated a = accepted(login(signedResponse(doc)));
        assertEquals(List.of(), a.attributes().get("role"));
    }

    @Test
    public void testEmptyAttributeValueIsKeptAsAnEmptyString() {
        final Document doc = draft();
        addAttribute(doc, "nickname", "");
        assertEquals(List.of(""), accepted(login(signedResponse(doc))).attributes().get("nickname"));
    }

    @Test
    public void testAttributeWithoutNameIsRefused() {
        controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = draft();
            addAttribute(doc, "x", "y");
            if (attack) {
                final List<Element> attributes = TestIdp.all(doc, Names.NS_SAML, "Attribute");
                attributes.get(attributes.size() - 1).removeAttribute("Name");
            }
            return signedResponse(doc);
        });
    }

    @Test
    public void testEncryptedAttributeIsRefused() {
        controlAndChange(Reason.UNSUPPORTED, attack -> {
            final Document doc = draft();
            if (attack) {
                first(doc, Names.NS_SAML, "AttributeStatement").appendChild(element(doc, Names.NS_SAML, "saml:EncryptedAttribute"));
            }
            return signedResponse(doc);
        });
    }

    @Test
    public void testResponseWithoutAttributesIsAccepted() {
        final TestIdp.ResponseSpec spec = TestIdp.response();
        spec.attributes.clear();
        assertTrue(accepted(login(spec.encoded())).attributes().isEmpty());
    }

    // ---- NameID ----------------------------------------------------------------------------------------------------

    @Test
    public void testCommentInsideTheNameIdIsNotPartOfTheValue() {
        final Document doc = draft();
        nameId(doc).setTextContent("");
        nameId(doc).appendChild(doc.createTextNode("alice"));
        nameId(doc).appendChild(doc.createComment(" a comment "));
        nameId(doc).appendChild(doc.createTextNode("@example.com"));
        assertEquals("alice@example.com", accepted(login(signedResponse(doc))).nameId().value());
    }

    @Test
    public void testCommentAddedToASignedNameIdDoesNotChangeTheValueTheSignatureCovers() {
        // The signature is computed without comments, so a comment can be added after signing. The value must be
        // the whole text, not the text node before the comment.
        final TestIdp.ResponseSpec spec = TestIdp.response();
        spec.nameId = "alice@example.com.evil";
        final Document doc = spec.document();
        final Element id = nameId(doc);
        id.setTextContent("");
        id.appendChild(doc.createTextNode("alice@example.com"));
        id.appendChild(doc.createComment("x"));
        id.appendChild(doc.createTextNode(".evil"));
        assertEquals("alice@example.com.evil", accepted(login(TestIdp.encode(doc))).nameId().value());
    }

    @Test
    public void testEmptyNameIdIsRefused() {
        for (final String value : new String[] { "", "   ", "\n\t" }) {
            controlAndChange(Reason.MALFORMED, attack -> encoded(s -> s.nameId = attack ? value : "alice@example.com"));
        }
    }

    @Test
    public void testNameIdWithOnlyACommentIsRefused() {
        controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = draft();
            if (attack) {
                nameId(doc).setTextContent("");
                nameId(doc).appendChild(doc.createComment("alice@example.com"));
            }
            return signedResponse(doc);
        });
    }

    @Test
    public void testNameIdWithAChildElementIsRefused() {
        controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = draft();
            if (attack) {
                nameId(doc).appendChild(element(doc, Names.NS_SAML, "saml:Extra"));
            }
            return signedResponse(doc);
        });
    }

    @Test
    public void testSubjectWithoutNameIdOrWithTwoIsRefused() {
        controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = draft();
            if (attack) {
                subject(doc).removeChild(nameId(doc));
            }
            return signedResponse(doc);
        });
        controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = draft();
            if (attack) {
                subject(doc).insertBefore(nameId(doc).cloneNode(true), nameId(doc));
            }
            return signedResponse(doc);
        });
    }

    private static Element encryptedNameId(final String value, final String mode) {
        final String plain = "<saml:NameID xmlns:saml=\"" + Names.NS_SAML
                + "\" Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress\">" + value + "</saml:NameID>";
        return ResponseTestSupport.encrypt(plain, mode).element("EncryptedID");
    }

    private static void replaceNameIdWithEncrypted(final Document doc, final Element encrypted) {
        final Element imported = (Element) doc.importNode(encrypted, true);
        subject(doc).replaceChild(imported, nameId(doc));
    }

    @Test
    public void testEncryptedNameIdIsDecrypted() {
        for (final String mode : new String[] { "cbc", "gcm" }) {
            final Document doc = draft();
            replaceNameIdWithEncrypted(doc, encryptedNameId("bob@example.com", mode));
            final LoginResult.Authenticated a = accepted(login(configWithKey(), signedResponse(doc)));
            assertEquals("bob@example.com", a.nameId().value(), mode);
            assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", a.nameId().format());
        }
    }

    @Test
    public void testEncryptedNameIdWithoutAKeyIsRefused() {
        final Document doc = draft();
        replaceNameIdWithEncrypted(doc, encryptedNameId("bob@example.com", "cbc"));
        final String message = signedResponse(doc);
        accepted(login(configWithKey(), message));
        refused(Reason.DECRYPTION_FAILED, login(TestIdp.config(), message));
    }

    @Test
    public void testEncryptedNameIdThatIsTamperedWithIsRefused() {
        controlAndChange(configWithKey(), Reason.DECRYPTION_FAILED, attack -> {
            final Document doc = draft();
            final Element encrypted = encryptedNameId("bob@example.com", "gcm");
            if (attack) {
                final Element data = child(encrypted, Names.NS_XENC, "EncryptedData");
                final Element value = child(child(data, Names.NS_XENC, "CipherData"), Names.NS_XENC, "CipherValue");
                final byte[] bytes = java.util.Base64.getDecoder().decode(value.getTextContent());
                bytes[bytes.length - 1] ^= 1;
                value.setTextContent(java.util.Base64.getEncoder().encodeToString(bytes));
            }
            replaceNameIdWithEncrypted(doc, encrypted);
            return signedResponse(doc);
        });
    }

    @Test
    public void testEncryptedIdThatIsNotANameIdIsRefused() {
        controlAndChange(configWithKey(), Reason.MALFORMED, attack -> {
            final Document doc = draft();
            final String plain = attack ? "<saml:Issuer xmlns:saml=\"" + Names.NS_SAML + "\">alice@example.com</saml:Issuer>"
                    : "<saml:NameID xmlns:saml=\"" + Names.NS_SAML + "\">alice@example.com</saml:NameID>";
            replaceNameIdWithEncrypted(doc, ResponseTestSupport.encrypt(plain, "cbc").element("EncryptedID"));
            return signedResponse(doc);
        });
    }

    @Test
    public void testSubjectWithBothNameIdAndEncryptedIdIsRefused() {
        controlAndChange(configWithKey(), Reason.MALFORMED, attack -> {
            final Document doc = draft();
            if (attack) {
                subject(doc).insertBefore(doc.importNode(encryptedNameId("bob@example.com", "cbc"), true), nameId(doc));
            }
            return signedResponse(doc);
        });
    }

    // ---- structure -------------------------------------------------------------------------------------------------

    @Test
    public void testRootThatIsNotAResponseIsRefused() {
        final Document doc = draft();
        final String message = TestIdp.encode(TestIdp.serialize(assertion(doc)));
        refused(Reason.MALFORMED, login(message));
        accepted(login(signedResponse(doc)));
    }

    @Test
    public void testUnsupportedVersionIsRefused() {
        controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = draft();
            response(doc).setAttribute("Version", attack ? "1.1" : "2.0");
            return signedResponse(doc);
        });
        controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = draft();
            assertion(doc).setAttribute("Version", attack ? "1.1" : "2.0");
            return signedResponse(doc);
        });
    }

    @Test
    public void testMissingIdsAreRefused() {
        controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = draft();
            if (attack) {
                assertion(doc).removeAttribute("ID");
            }
            return signedResponse(doc);
        });
    }

    @Test
    public void testAssertionWithoutRequiredPartsIsRefused() {
        for (final String part : new String[] { "Subject", "Conditions", "AuthnStatement" }) {
            controlAndChange(Reason.MALFORMED, attack -> {
                final Document doc = draft();
                if (attack) {
                    assertion(doc).removeChild(child(assertion(doc), Names.NS_SAML, part));
                }
                return signedResponse(doc);
            });
        }
    }

    @Test
    public void testAssertionWithTwoAuthnStatementsIsRefused() {
        controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = draft();
            if (attack) {
                final Element statement = child(assertion(doc), Names.NS_SAML, "AuthnStatement");
                assertion(doc).insertBefore(statement.cloneNode(true), statement);
            }
            return signedResponse(doc);
        });
    }

    @Test
    public void testResponseWithoutStatusIsRefused() {
        controlAndChange(Reason.MALFORMED, attack -> {
            final Document doc = draft();
            if (attack) {
                response(doc).removeChild(child(response(doc), Names.NS_SAMLP, "Status"));
            }
            return signedResponse(doc);
        });
    }

    @Test
    public void testSignedAssertionAndSignedResponseTogetherAreAccepted() {
        final Document doc = draft();
        signAssertion(doc);
        final LoginResult.Authenticated a = accepted(login(signedResponse(doc)));
        assertEquals("alice@example.com", a.nameId().value());
    }
}
