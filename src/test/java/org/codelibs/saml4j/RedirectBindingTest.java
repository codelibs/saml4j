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

import static org.codelibs.saml4j.LogoutTestSupport.assertEnded;
import static org.codelibs.saml4j.LogoutTestSupport.assertKeptAndAnswered;
import static org.codelibs.saml4j.LogoutTestSupport.assertRejected;
import static org.codelibs.saml4j.LogoutTestSupport.handle;
import static org.codelibs.saml4j.LogoutTestSupport.sp;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.regex.Pattern;

import org.codelibs.saml4j.LogoutOutcome.Action;
import org.codelibs.saml4j.LogoutTestSupport.Request;
import org.codelibs.saml4j.internal.Names;
import org.codelibs.saml4j.internal.RedirectBinding;
import org.codelibs.saml4j.internal.Refusal;
import org.codelibs.saml4j.internal.Text;
import org.junit.jupiter.api.Test;

public class RedirectBindingTest {

    private static final Pattern ANY_CONTROL = Pattern.compile("[\\p{Cntrl}\\u0085\\u2028\\u2029]");

    private static final String USER_BOB = "bob@example.com";

    /** The encoded message parameter value of a request. */
    private static String message(final Request r) {
        return Text.urlEncode(TestIdp.deflate(r.xml()));
    }

    /**
     * A query for {@code SAMLRequest} signed by the IdP over exactly the strings given (they are used raw).
     *
     * @param relayRaw the raw RelayState value, or {@code null}
     * @param sigAlg the SigAlg URI, put into the query percent-encoded
     */
    private static String signedOver(final String messageRaw, final String relayRaw, final String sigAlg, final PrivateKey key,
            final String jca) {
        final StringBuilder q = new StringBuilder("SAMLRequest=").append(messageRaw);
        if (relayRaw != null) {
            q.append("&RelayState=").append(relayRaw);
        }
        q.append("&SigAlg=").append(Text.urlEncode(sigAlg));
        final String signature = TestIdp.rsaSign(q.toString(), key, jca);
        return q.append("&Signature=").append(Text.urlEncode(signature)).toString();
    }

    private static String signedOver(final Request r, final String sigAlg, final String jca) {
        return signedOver(message(r), null, sigAlg, TestIdp.IDP_KEY, jca);
    }

    /** The part of a query from the first parameter after the SAMLRequest on, {@code &...}. */
    private static String tail(final String query) {
        return query.substring(query.indexOf('&'));
    }

    // ---- parameter names -------------------------------------------------------------------------------------------

    @Test
    public void testPrefixedNameIsNotTheMessageParameter() {
        final ServiceProvider sp = sp();
        final String legit = new Request("_legit").nameId(USER_BOB).signed();
        final String legitValue = legit.substring("SAMLRequest=".length(), legit.indexOf('&'));
        final String evilValue = message(new Request("_evil"));

        // control: an unknown parameter named like the message does not disturb the genuine one
        assertKeptAndAnswered(handle(sp, "xSAMLRequest=" + evilValue + "&" + legit));

        // the signature was made over the legit message, the evil one is the real SAMLRequest
        final String mixed = "xSAMLRequest=" + legitValue + "&SAMLRequest=" + evilValue + tail(legit);
        final LogoutOutcome o = handle(sp, mixed);
        assertRejected(Reason.INVALID_SIGNATURE, o);
        assertNotEquals(Action.END_SESSION, o.action());
    }

    @Test
    public void testNameThatIsAPrefixOrSuffixOrDifferentCaseIsIgnored() {
        final ServiceProvider sp = sp();
        final String evil = message(new Request("_evil"));
        final String[] decoys = { "SAMLRequestX", "xSAMLRequest", "samlrequest", "SAMLREQUEST", "SAMLRequest%20", "SAML%52equest2",
                "SAMLRequest[]", "a.SAMLRequest" };
        int n = 0;
        for (final String decoy : decoys) {
            final String legit = new Request("_legit" + n++).signed();
            assertEnded(handle(sp, decoy + "=" + evil + "&" + legit));
        }
    }

    @Test
    public void testPercentEncodedNameCountsAsTheSameName() {
        final ServiceProvider sp = sp();
        final String legit = new Request("_legit").signed();
        final String evilValue = message(new Request("_evil").nameId(USER_BOB));

        // the same name once, written with an escape, is the message parameter (and it verifies)
        final String escaped = "SAMLReques%74" + legit.substring("SAMLRequest".length());
        assertEnded(handle(sp, escaped));

        // twice, one of them escaped: refused as a duplicate, whichever comes first
        final String legit2 = new Request("_legit2").signed();
        assertRejected(Reason.BAD_REQUEST, handle(sp, "SAMLReques%74=" + evilValue + "&" + legit2));
        assertRejected(Reason.BAD_REQUEST, handle(sp, legit2 + "&SAMLReques%74=" + evilValue));
        assertRejected(Reason.BAD_REQUEST, handle(sp, "%53AMLRequest=" + evilValue + "&" + legit2));

        // the control for the refusals above: the genuine query on its own is accepted
        assertEnded(handle(sp, new Request("_legit3").signed()));
    }

    @Test
    public void testRepeatedParametersAreRefused() {
        final ServiceProvider sp = sp();
        final String relay = "r1";
        final Request r = new Request("_lr");
        final String signedWithRelay = r.signed(relay);
        final String sigAlgRaw = signedWithRelay.replaceAll(".*[&?]SigAlg=([^&]*).*", "$1");
        final String signatureRaw = signedWithRelay.replaceAll(".*[&?]Signature=([^&]*).*", "$1");
        assertTrue(!sigAlgRaw.isEmpty() && !signatureRaw.isEmpty());

        assertEnded(handle(sp, new Request("_ok").signed(relay)));

        assertRejected(Reason.BAD_REQUEST, handle(sp, new Request("_lr1").signed(relay) + "&RelayState=r2"));
        assertRejected(Reason.BAD_REQUEST, handle(sp, new Request("_lr2").signed(relay) + "&RelayState=" + relay));
        assertRejected(Reason.BAD_REQUEST, handle(sp, new Request("_lr3").signed(relay) + "&SigAlg=" + sigAlgRaw));
        assertRejected(Reason.BAD_REQUEST, handle(sp, new Request("_lr4").signed(relay) + "&Signature=AAAA"));
        assertRejected(Reason.BAD_REQUEST, handle(sp, "Signature=AAAA&" + new Request("_lr5").signed(relay)));
        assertRejected(Reason.BAD_REQUEST, handle(sp, new Request("_lr6").signed(relay) + "&SAMLRequest=" + message(new Request("_lr7"))));
        assertRejected(Reason.BAD_REQUEST, handle(sp, new Request("_lr8").signed(relay) + "&%53igAlg=" + sigAlgRaw));
        // an identical repeat is still a repeat
        final String again = new Request("_lr9").signed(relay);
        assertRejected(Reason.BAD_REQUEST, handle(sp, again + again.substring(again.indexOf("&RelayState="), again.indexOf("&SigAlg="))));
    }

    @Test
    public void testRepeatedResponseParameterIsRefused() {
        final ServiceProvider sp = sp();
        final String response = LogoutTestSupport.redirectQuery("SAMLResponse", TestIdp.logoutResponseXml("_resp1", Names.STATUS_SUCCESS),
                null, TestIdp.IDP_KEY);
        final String again =
                LogoutTestSupport.redirectQuery("SAMLResponse", TestIdp.logoutResponseXml("_resp2", Names.STATUS_SUCCESS), null, null);
        assertRejected(Reason.BAD_REQUEST, handle(sp, response + "&" + again + "&x=1"));
        assertEquals(Action.KEEP_SESSION, handle(sp, response).action());
    }

    @Test
    public void testUnknownParametersAreIgnoredAndDoNotBreakVerification() {
        final ServiceProvider sp = sp();
        assertEnded(handle(sp, new Request("_lr0").signed("rs")));
        assertEnded(handle(sp, "utm_source=mail&" + new Request("_lr1").signed("rs")));
        assertEnded(handle(sp, new Request("_lr2").signed("rs") + "&utm_source=mail&fbclid=a%2Bb"));
        final String q = new Request("_lr3").signed("rs");
        final String middle = q.replace("&SigAlg=", "&extra=1&&novalue&=x&SigAlg=");
        assertEnded(handle(sp, middle));
        // unknown values are never decoded, so a broken escape in one of them does not matter
        assertEnded(handle(sp, new Request("_lr4").signed("rs") + "&note=%ZZ%"));
    }

    @Test
    public void testParameterOrderDoesNotMatter() {
        final ServiceProvider sp = sp();
        final String q = new Request("_lr1").signed("rs");
        final String[] parts = q.split("&");
        assertEquals(4, parts.length);
        // SAMLRequest, RelayState, SigAlg, Signature  ->  Signature, SigAlg, RelayState, SAMLRequest
        final String reversed = String.join("&", parts[3], parts[2], parts[1], parts[0]);
        assertEnded(handle(sp, reversed));
    }

    @Test
    public void testParseKeepsRawValuesAndDoesNotTurnPlusIntoSpace() {
        final RedirectBinding.Query q = RedirectBinding.parse("SAMLRequest=a+b%2Fc%3D&Foo=%ZZ&SigAlg", 1000);
        assertEquals("a+b%2Fc%3D", q.raw("SAMLRequest"));
        assertEquals("a+b/c=", q.decoded("SAMLRequest"));
        assertNull(q.raw("Foo"));
        assertEquals("", q.raw("SigAlg"));
        assertNull(q.raw("RelayState"));
        assertNull(q.decoded("RelayState"));
    }

    // ---- plus signs and escapes ------------------------------------------------------------------------------------

    /** A request whose deflated, base64 form contains a plus sign; {@code skip} selects a different one. */
    private static Request requestWithPlus(final int skip) {
        int found = 0;
        for (int i = 0; i < 20_000; i++) {
            final Request candidate = new Request("_p" + i);
            if (TestIdp.deflate(candidate.xml()).contains("+") && found++ == skip) {
                return candidate;
            }
        }
        throw new AssertionError("no message with a plus sign in its base64 form was found");
    }

    @Test
    public void testPlusInBase64ValuesIsPreserved() {
        final ServiceProvider sp = sp();

        // as sent with %2B (what this library and most senders do)
        final Request first = requestWithPlus(0);
        final String encoded = signedOver(message(first), null, Names.RSA_SHA256, TestIdp.IDP_KEY, "SHA256withRSA");
        assertTrue(encoded.contains("%2B"));
        assertEnded(handle(sp, encoded));

        // as sent with a literal '+', signed over that exact text
        final Request second = requestWithPlus(1);
        final String b64 = TestIdp.deflate(second.xml());
        assertTrue(b64.contains("+"));
        final String literal = signedOver(b64, null, Names.RSA_SHA256, TestIdp.IDP_KEY, "SHA256withRSA");
        assertTrue(literal.contains("+"));
        assertEnded(handle(sp, literal));
    }

    @Test
    public void testPlusInTheSignatureIsPreserved() {
        final ServiceProvider sp = sp();
        for (int i = 0; i < 2000; i++) {
            final Request r = new Request("_s" + i);
            final String raw = message(r);
            final StringBuilder q =
                    new StringBuilder("SAMLRequest=").append(raw).append("&SigAlg=").append(Text.urlEncode(Names.RSA_SHA256));
            final String sig = TestIdp.rsaSign(q.toString(), TestIdp.IDP_KEY, "SHA256withRSA");
            if (sig.contains("+")) {
                // the signature as a literal base64 text, '+' and all
                assertEnded(handle(sp, q + "&Signature=" + sig));
                return;
            }
        }
        throw new AssertionError("no signature with a plus sign was found");
    }

    private static ServiceProvider relaxed() {
        return ServiceProvider.create(TestIdp.configWithLogout().wantLogoutSigned(false).build());
    }

    @Test
    public void testMalformedPercentEscapeIsRefused() {
        final ServiceProvider sp = sp();
        assertEnded(handle(sp, new Request("_ok").signed("rs")));
        final String legit = new Request("_lr1").signed("rs");

        // in a parameter name, relevant or not
        assertRejected(Reason.BAD_REQUEST, handle(sp, "SAMLReques%7=x&" + legit));
        assertRejected(Reason.BAD_REQUEST, handle(sp, "bad%ZZ=1&" + legit));
        assertRejected(Reason.BAD_REQUEST, handle(sp, legit + "&bad%"));
        // truncated at the very end
        assertRejected(Reason.BAD_REQUEST, handle(sp, legit + "&tail%4"));

        // in the value of each relevant parameter
        final ServiceProvider relaxed = relaxed();
        assertRejected(Reason.BAD_REQUEST, handle(relaxed, "SAMLRequest=%ZZ"));
        assertRejected(Reason.BAD_REQUEST, handle(relaxed, "SAMLRequest=%4"));
        assertRejected(Reason.BAD_REQUEST, handle(relaxed, "SAMLRequest=%FF%FE"));
        final String q = new Request("_lr2").signed("rs");
        assertRejected(Reason.BAD_REQUEST, handle(sp, q.replaceAll("SigAlg=[^&]*", "SigAlg=%ZZ")));
        assertRejected(Reason.BAD_REQUEST, handle(sp, new Request("_lr3").signed("rs").replaceAll("Signature=[^&]*", "Signature=%ZZ")));

        // a RelayState that is signed but cannot be decoded
        final String badRelay = signedOver(message(new Request("_lr4")), "%ZZ", Names.RSA_SHA256, TestIdp.IDP_KEY, "SHA256withRSA");
        assertRejected(Reason.BAD_REQUEST, handle(sp, badRelay));
    }

    // ---- SigAlg ----------------------------------------------------------------------------------------------------

    @Test
    public void testRsaSha2AlgorithmsAreAccepted() {
        final ServiceProvider sp = sp();
        assertEnded(handle(sp, signedOver(new Request("_a256"), Names.RSA_SHA256, "SHA256withRSA")));
        assertEnded(handle(sp, signedOver(new Request("_a384"), Names.RSA_SHA384, "SHA384withRSA")));
        assertEnded(handle(sp, signedOver(new Request("_a512"), Names.RSA_SHA512, "SHA512withRSA")));
    }

    @Test
    public void testAlgorithmOutsideTheRsaSha2ListIsRefused() {
        final String[] uris = { "http://example.com/unknown-signature-algorithm", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
                "http://www.w3.org/2000/09/xmldsig#dsa-sha1", "http://www.w3.org/2001/04/xmldsig-more#rsa-md5",
                Names.RSA_SHA256.toUpperCase(), Names.RSA_SHA256 + " ", " " + Names.RSA_SHA256, "SHA256withRSA", "", "none",
                "http://www.w3.org/2001/04/xmldsig-more#rsa-sha224" };
        for (final boolean deprecated : new boolean[] { false, true }) {
            final ServiceProvider sp = sp(TestIdp.configWithLogout().allowDeprecatedAlg(deprecated));
            assertEnded(handle(sp, signedOver(new Request("_ctl"), Names.RSA_SHA256, "SHA256withRSA")));
            int n = 0;
            for (final String uri : uris) {
                final LogoutOutcome o = handle(sp, signedOver(new Request("_u" + n++), uri, "SHA256withRSA"));
                assertRejected(Reason.INVALID_SIGNATURE, o);
                assertTrue(o.detail().contains("algorithm"), "the algorithm gate, not the verification: " + o.detail());
            }
        }
    }

    @Test
    public void testRsaSha1IsAcceptedOnlyWhenDeprecatedAlgorithmsAreAllowed() {
        final String sha1 = Names.RSA_SHA1;
        final String query = signedOver(new Request("_lr1"), sha1, "SHA1withRSA");

        final LogoutOutcome refused = handle(sp(), query);
        assertRejected(Reason.INVALID_SIGNATURE, refused);
        assertTrue(refused.detail().contains("algorithm"), refused.detail());

        final ServiceProvider lenient = sp(TestIdp.configWithLogout().allowDeprecatedAlg(true));
        assertEnded(handle(lenient, query));
        // the setting does not make an unrelated algorithm acceptable
        assertRejected(Reason.INVALID_SIGNATURE,
                handle(lenient, signedOver(new Request("_lr2"), "http://www.w3.org/2000/09/xmldsig#dsa-sha1", "SHA1withRSA")));
    }

    @Test
    public void testSignatureMadeWithAnotherAlgorithmThanDeclaredIsRefused() {
        final ServiceProvider sp = sp(TestIdp.configWithLogout().allowDeprecatedAlg(true));
        assertEnded(handle(sp, signedOver(new Request("_lr0"), Names.RSA_SHA512, "SHA512withRSA")));
        final LogoutOutcome o = handle(sp, signedOver(new Request("_lr1"), Names.RSA_SHA512, "SHA256withRSA"));
        assertRejected(Reason.INVALID_SIGNATURE, o);
        assertTrue(o.detail().contains("verify"), o.detail());
        assertRejected(Reason.INVALID_SIGNATURE, handle(sp, signedOver(new Request("_lr2"), Names.RSA_SHA1, "SHA256withRSA")));
    }

    @Test
    public void testSignatureThatIsNotBase64IsRefused() {
        final ServiceProvider sp = sp();
        final String q = new Request("_lr1").signed();
        assertRejected(Reason.INVALID_SIGNATURE, handle(sp, q.replaceAll("Signature=[^&]*", "Signature=not*base64!")));
        assertRejected(Reason.INVALID_SIGNATURE, handle(sp, new Request("_lr2").signed().replaceAll("Signature=[^&]*", "Signature=")));
        assertEnded(handle(sp, new Request("_lr3").signed()));
    }

    @Test
    public void testSigAlgWithLineBreakIsRefusedWithAPlainDetail() {
        final ServiceProvider sp = sp();
        final LogoutOutcome o = handle(sp, signedOver(new Request("_lr1"), "http://x.example.com/a\r\nINJECTED", "SHA256withRSA"));
        assertRejected(Reason.INVALID_SIGNATURE, o);
        assertFalse(ANY_CONTROL.matcher(o.detail()).find(), o.detail());
        assertEnded(handle(sp, new Request("_lr2").signed()));
    }

    @Test
    public void testSignatureWithoutSigAlgAndTheReverseAreRefused() {
        final ServiceProvider sp = sp();
        final String q = new Request("_lr1").signed();
        assertEnded(handle(sp, q));
        final String noAlg = new Request("_lr2").signed().replaceAll("&SigAlg=[^&]*", "");
        assertFalse(noAlg.contains("SigAlg"));
        assertRejected(Reason.BAD_REQUEST, handle(sp, noAlg));
        final String noSignature = new Request("_lr3").signed().replaceAll("&Signature=[^&]*", "");
        assertFalse(noSignature.contains("Signature="));
        assertRejected(Reason.BAD_REQUEST, handle(sp, noSignature));
        // an empty value is a value, so it is not "missing"
        final String emptyAlg = new Request("_lr4").signed().replaceAll("SigAlg=[^&]*", "SigAlg=");
        assertRejected(Reason.INVALID_SIGNATURE, handle(sp, emptyAlg));
    }

    @Test
    public void testSignatureParametersDoNotMakeAnUnsignedConfigurationVerify() {
        // with signatures optional, a SigAlg alone is still refused rather than ignored
        final ServiceProvider sp = LogoutTestSupport.spAcceptingUnsigned();
        assertEnded(handle(sp, new Request("_lr1").unsigned()));
        assertRejected(Reason.BAD_REQUEST, handle(sp, new Request("_lr2").unsigned() + "&SigAlg=" + Text.urlEncode(Names.RSA_SHA256)));
        assertRejected(Reason.BAD_REQUEST, handle(sp, new Request("_lr3").unsigned() + "&Signature=AAAA"));
    }

    // ---- payload encoding and size ---------------------------------------------------------------------------------

    @Test
    public void testPayloadThatIsNotDeflatedIsRefused() {
        final ServiceProvider sp = sp();
        assertEnded(handle(sp, new Request("_ctl").signed()));
        // the POST-binding encoding (base64 of the plain XML) is not valid in the redirect binding
        final String plain = Base64.getEncoder().encodeToString(new Request("_lr1").xml().getBytes(StandardCharsets.UTF_8));
        final String query = signedOver(Text.urlEncode(plain), null, Names.RSA_SHA256, TestIdp.IDP_KEY, "SHA256withRSA");
        assertRejected(Reason.MALFORMED, handle(sp, query));
        assertRejected(Reason.MALFORMED, handle(relaxed(), "SAMLRequest=" + Text.urlEncode(plain)));
    }

    @Test
    public void testTruncatedAndGarbledPayloadsAreRefused() {
        final byte[] deflated = Base64.getDecoder().decode(TestIdp.deflate(new Request("_lr1").xml()));
        final byte[] cut = Arrays.copyOf(deflated, deflated.length / 2);
        assertRejected(Reason.MALFORMED, handle(relaxed(), "SAMLRequest=" + Text.urlEncode(Base64.getEncoder().encodeToString(cut))));
        assertRejected(Reason.MALFORMED, handle(relaxed(), "SAMLRequest=" + Text.urlEncode("!!not base64!!")));
        assertRejected(Reason.MALFORMED, handle(relaxed(), "SAMLRequest="));
        assertRejected(Reason.MALFORMED, handle(relaxed(), "SAMLRequest"));
        // valid deflate of something that is not XML
        assertRejected(Reason.MALFORMED, handle(relaxed(), "SAMLRequest=" + Text.urlEncode(TestIdp.deflate("this is not xml"))));
    }

    @Test
    public void testMessageWithADoctypeIsRefused() {
        final ServiceProvider sp = sp();
        assertEnded(handle(sp, new Request("_ctl").signed()));
        final String xml = "<!DOCTYPE x [<!ENTITY e \"v\">]>" + new Request("_lr1").xml();
        assertRejected(Reason.MALFORMED, handle(sp, LogoutTestSupport.redirectQuery("SAMLRequest", xml, null, TestIdp.IDP_KEY)));
    }

    @Test
    public void testHighlyCompressedPayloadIsRefused() {
        final ServiceProvider sp = sp();
        // control: the same shape with a modest comment
        final String small = new Request("_lr0").xml().replace("<saml:Issuer>", "<!--" + "a".repeat(10_000) + "--><saml:Issuer>");
        assertEnded(handle(sp, LogoutTestSupport.redirectQuery("SAMLRequest", small, null, TestIdp.IDP_KEY)));

        final String bomb = new Request("_lr1").xml().replace("<saml:Issuer>", "<!--" + "a".repeat(5 * 1024 * 1024) + "--><saml:Issuer>");
        final String query = LogoutTestSupport.redirectQuery("SAMLRequest", bomb, null, TestIdp.IDP_KEY);
        assertTrue(query.length() < 100_000, "the bomb must be small on the wire: " + query.length());
        assertRejected(Reason.TOO_LARGE, handle(sp, query));

        // not XML at all: refused for its size before it is parsed
        final String zeros = TestIdp.deflate("0".repeat(5 * 1024 * 1024));
        assertRejected(Reason.TOO_LARGE, handle(relaxed(), "SAMLRequest=" + Text.urlEncode(zeros)));
    }

    @Test
    public void testSizeLimitFollowsTheConfiguration() {
        final String padded = new Request("_lr1").xml().replace("<saml:Issuer>", "<!--" + "a".repeat(20_000) + "--><saml:Issuer>");
        final String query = LogoutTestSupport.redirectQuery("SAMLRequest", padded, null, TestIdp.IDP_KEY);
        assertRejected(Reason.TOO_LARGE, handle(sp(TestIdp.configWithLogout().maxMessageSize(10_000)), query));
        assertEnded(handle(sp(TestIdp.configWithLogout().maxMessageSize(100_000)), query));
    }

    @Test
    public void testOversizeQueryIsRefused() {
        final ServiceProvider sp = sp(TestIdp.configWithLogout().maxMessageSize(1024));
        assertEnded(handle(sp, new Request("_ctl").signed()));

        // longer than twice the message limit plus the room for the other parameters
        assertRejected(Reason.TOO_LARGE, handle(sp, "SAMLRequest=" + "A".repeat(7000)));
        assertRejected(Reason.TOO_LARGE, handle(sp, new Request("_lr1").signed() + "&padding=" + "x".repeat(7000)));
        assertRejected(Reason.TOO_LARGE, handle(sp, "padding=" + "x".repeat(7000)));

        // within the query limit, but the base64 text is more than 1024 bytes
        assertRejected(Reason.TOO_LARGE,
                handle(sp(TestIdp.configWithLogout().maxMessageSize(1024).wantLogoutSigned(false)), "SAMLRequest=" + "A".repeat(4000)));
    }

    @Test
    public void testMissingQueryIsRefused() {
        final ServiceProvider sp = sp();
        assertEnded(handle(sp, new Request("_ctl").signed()));
        assertRejected(Reason.BAD_REQUEST, handle(sp, null));
        assertRejected(Reason.BAD_REQUEST, handle(sp, ""));
    }

    @Test
    public void testParseRefusesWithTheExpectedReasons() {
        assertEquals(Reason.BAD_REQUEST,
                assertThrows(Refusal.class, () -> RedirectBinding.parse("SAMLRequest=a&SAMLRequest=b", 1000)).reason());
        assertEquals(Reason.BAD_REQUEST,
                assertThrows(Refusal.class, () -> RedirectBinding.parse("SAMLReques%74=a&SAMLRequest=b", 1000)).reason());
        assertEquals(Reason.TOO_LARGE,
                assertThrows(Refusal.class, () -> RedirectBinding.parse("SAMLRequest=" + "a".repeat(100), 50)).reason());
        assertEquals(Reason.BAD_REQUEST, assertThrows(Refusal.class, () -> RedirectBinding.parse("", 50)).reason());
        // two different names are fine
        assertEquals("b", RedirectBinding.parse("SAMLRequest=a&SAMLResponse=b", 1000).raw("SAMLResponse"));
    }
}
