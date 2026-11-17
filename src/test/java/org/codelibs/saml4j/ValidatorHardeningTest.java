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
import static org.codelibs.saml4j.ResponseTestSupport.configWithKey;
import static org.codelibs.saml4j.ResponseTestSupport.first;
import static org.codelibs.saml4j.ResponseTestSupport.refused;
import static org.codelibs.saml4j.ResponseTestSupport.response;
import static org.codelibs.saml4j.ResponseTestSupport.signAssertion;
import static org.codelibs.saml4j.ResponseTestSupport.signResponse;
import static org.codelibs.saml4j.ResponseTestSupport.unsigned;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.List;

import org.codelibs.saml4j.internal.Names;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class ValidatorHardeningTest {

    private static LoginResult login(final SamlConfig.Builder c, final Document doc) {
        return ServiceProvider.create(c.build()).finishLogin(TestIdp.encode(doc), PENDING);
    }

    private static void split(final Element e, final String... parts) {
        e.setTextContent("");
        final Document d = e.getOwnerDocument();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) {
                e.appendChild(d.createComment("x"));
            }
            e.appendChild(i % 2 == 0 ? d.createTextNode(parts[i]) : d.createCDATASection(parts[i]));
        }
    }

    // ---- probe 2: comment / CDATA / multiple text nodes -------------------------------------------------------------

    @Test
    public void nameIdSplitByCommentAndCdataIsReadAsOneValue_noIssue() {
        for (final boolean signAssertion : new boolean[] { false, true }) {
            final Document doc = unsigned(TestIdp.response());
            split(first(doc, Names.NS_SAML, "NameID"), "a@x", "-cdata-", ".evil");
            if (signAssertion) {
                signAssertion(doc);
            } else {
                signResponse(doc);
            }
            final LoginResult.Authenticated a = accepted(login(TestIdp.config(), doc));
            assertEquals("a@x-cdata-.evil", a.nameId().value());
        }
    }

    @Test
    public void audienceAndIssuerSplitByCommentAreConsistent_noIssue() {
        final Document doc = unsigned(TestIdp.response());
        split(first(doc, Names.NS_SAML, "Audience"), "https://fess.example.com/", "x", "sso/metadata");
        // the CDATA in the middle is read as text, so the audience is "https://fess.example.com/xsso/metadata": refused
        signResponse(doc);
        refused(Reason.WRONG_AUDIENCE, login(TestIdp.config(), doc));
    }

    @Test
    public void commentInsertedAfterSigningDoesNotChangeTheValue_noIssue() {
        final Document doc = TestIdp.response().document();
        final Element nameId = first(doc, Names.NS_SAML, "NameID");
        nameId.insertBefore(doc.createComment("c"), nameId.getFirstChild());
        final LoginResult.Authenticated a = accepted(login(TestIdp.config(), doc));
        assertEquals("alice@example.com", a.nameId().value());
    }

    // ---- probe 3: encrypted, unsigned Response ---------------------------------------------------------------------

    private static LoginResult unsignedWithPlain(final String plain, final String mode, final boolean inResponseTo) {
        final Element enc = ResponseTestSupport.encrypt(plain, mode).element("EncryptedAssertion");
        final Document doc = ResponseTestSupport.responseWithEncryptedAssertion(enc, false);
        if (!inResponseTo) {
            response(doc).removeAttribute("InResponseTo");
        }
        return login(configWithKey(), doc);
    }

    @Test
    public void innerSignatureIsRequiredAfterDecryption_noIssue() {
        // response unsigned, assertion encrypted and unsigned: refused, and not told apart from a failed decryption
        refused(Reason.DECRYPTION_FAILED, unsignedWithPlain(ResponseTestSupport.plainAssertion(), "cbc", true));
        // response unsigned, assertion encrypted and signed inside: accepted
        final Document d = unsigned(TestIdp.response());
        signAssertion(d);
        accepted(unsignedWithPlain(TestIdp.serialize(assertion(d)), "gcm", true));
        // signature inside refers to the response id (outside the decrypted block)
        final Document d2 = unsigned(TestIdp.response());
        final String respId = response(d2).getAttribute("ID");
        TestIdp.sign(assertion(d2), TestIdp.IDP_KEY, Names.RSA_SHA256, ResponseTestSupport.SHA256);
        final String xml = TestIdp.serialize(assertion(d2));
        final String assertionId = assertion(d2).getAttribute("ID");
        refused(Reason.DECRYPTION_FAILED, unsignedWithPlain(xml.replace("\"#" + assertionId + "\"", "\"#" + respId + "\""), "cbc", true));
    }

    /** F-B1: on the unauthenticated path the reason reveals whether the decrypted bytes were a well-formed element. */
    @Test
    public void decryptionOutcomeIsTheSameForWellFormedAndNotWellFormedPlaintext() {
        final LoginResult.Rejected wellFormed = assertInstanceOf(LoginResult.Rejected.class, unsignedWithPlain("<a/>", "cbc", true));
        final LoginResult.Rejected garbage = assertInstanceOf(LoginResult.Rejected.class, unsignedWithPlain("not xml", "cbc", true));
        assertEquals(garbage, wellFormed, "oracle: " + wellFormed + " vs " + garbage);
    }

    /** F-B2: an unsigned Response without InResponseTo makes the SP do RSA decryption before anything is authenticated. */
    @Test
    public void garbageEncryptedAssertionIsRefusedBeforeDecryptionWhenNothingIsAuthenticated() {
        final LoginResult.Rejected r = assertInstanceOf(LoginResult.Rejected.class, unsignedWithPlain("anything", "cbc", false));
        assertNotEquals(Reason.DECRYPTION_FAILED, r.reason(), "decryption was attempted: " + r);
    }

    // ---- probe 5: replay -------------------------------------------------------------------------------------------

    @Test
    public void aRefusedMessageDoesNotRegisterTheIdAndReplayIsCaughtWhateverTheOuterPartsSay_noIssue() {
        final ServiceProvider sp = ServiceProvider.create(TestIdp.config().build());
        final TestIdp.ResponseSpec bad = TestIdp.response();
        bad.assertionId = "_sameid";
        bad.confirmationNotOnOrAfter = TestIdp.NOW.minusSeconds(3600); // refused: expired
        bad.signResponse = false;
        bad.signAssertion = true;
        refused(Reason.EXPIRED, sp.finishLogin(bad.encoded(), PENDING));
        final TestIdp.ResponseSpec good = TestIdp.response();
        good.assertionId = "_sameid";
        good.signResponse = false;
        good.signAssertion = true;
        final Document doc = good.document();
        accepted(sp.finishLogin(TestIdp.encode(doc), PENDING));
        // the outer response is unsigned: change its id and destination and replay the same signed assertion
        response(doc).setAttribute("ID", "_other");
        response(doc).removeAttribute("Destination");
        refused(Reason.REPLAYED, sp.finishLogin(TestIdp.encode(doc), PENDING));
    }

    // ---- probe 6 --------------------------------------------------------------------------------------------------

    /** F-B3: attacker text in the Issuer of an unsigned Response reaches the detail with bidi/format characters intact. */
    @Test
    public void detailStripsBidiAndFormatCharactersFromMessageText() {
        final TestIdp.ResponseSpec s = TestIdp.response();
        s.issuer = "‮evil​⁦";
        s.signResponse = false;
        s.signAssertion = true;
        final LoginResult.Rejected r = assertInstanceOf(LoginResult.Rejected.class,
                ServiceProvider.create(TestIdp.config().build()).finishLogin(s.encoded(), PENDING));
        assertEquals(Reason.WRONG_ISSUER, r.reason());
        assertFalse(r.detail().chars().anyMatch(c -> Character.getType(c) == Character.FORMAT), "detail: " + r.detail());
    }

    @Test
    public void attributeValueWithNestedElementIsDroppedSilently_info() {
        final Document doc = unsigned(TestIdp.response());
        final Element v = first(doc, Names.NS_SAML, "AttributeValue");
        v.appendChild(ResponseTestSupport.element(doc, Names.NS_SAML, "saml:x"));
        signResponse(doc);
        final LoginResult.Authenticated a = accepted(login(TestIdp.config(), doc));
        assertEquals(List.of("dev"), a.attributes().get("memberOf"));
    }
}
