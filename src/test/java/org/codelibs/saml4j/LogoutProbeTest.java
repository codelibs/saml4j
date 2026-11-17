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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import org.codelibs.saml4j.LogoutOutcome.Action;
import org.codelibs.saml4j.internal.Names;
import org.codelibs.saml4j.internal.Text;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

/** Security review probes: each test asserts the secure behaviour and is expected to be GREEN on current code. */
public class LogoutProbeTest {

    private static final String DIGEST = "http://www.w3.org/2001/04/xmlenc#sha256";

    private static LogoutOutcome h(final ServiceProvider sp, final String q) {
        return LogoutTestSupport.handle(sp, q);
    }

    private static LogoutTestSupport.Request req(final String id) {
        return new LogoutTestSupport.Request(id);
    }

    // ---- probe 1: redirect binding ----

    @Test
    public void p1_percentEncodedParameterNameIsTheSameParameter() {
        final String q = req("_a1").signed().replace("SAMLRequest=", "%53AMLRequest=");
        assertEquals(Action.END_SESSION, h(LogoutTestSupport.sp(), q).action());
    }

    @Test
    public void p1_duplicateViaEncodedNameRefused() {
        final String q = req("_a2").signed();
        final String dup = q + "&%53AMLRequest=" + q.substring("SAMLRequest=".length(), q.indexOf('&'));
        LogoutTestSupport.assertRejected(Reason.BAD_REQUEST, h(LogoutTestSupport.sp(), dup));
        LogoutTestSupport.assertRejected(Reason.BAD_REQUEST, h(LogoutTestSupport.sp(), q + "&SigAlg=x"));
        LogoutTestSupport.assertRejected(Reason.BAD_REQUEST, h(LogoutTestSupport.sp(), q + "&Signature=AAAA"));
        LogoutTestSupport.assertRejected(Reason.BAD_REQUEST, h(LogoutTestSupport.sp(), q + "&RelayState=x&RelayState=y"));
    }

    @Test
    public void p1_caseVariantNamesAreNotTheMessageNorTheSignature() {
        final String q = req("_a3").signed();
        // lower-case message name: no SAMLRequest at all
        LogoutTestSupport.assertRejected(Reason.BAD_REQUEST, h(LogoutTestSupport.sp(), q.replace("SAMLRequest=", "samlrequest=")));
        // lower-case signature names: treated as absent -> unsigned -> refused when signing is wanted
        LogoutTestSupport.assertRejected(Reason.NOT_SIGNED,
                h(LogoutTestSupport.sp(), q.replace("&Signature=", "&signature=").replace("&SigAlg=", "&sigalg=")));
    }

    @Test
    public void p1_requestAndResponseTogetherRefused() {
        final String q = req("_a4").signed();
        LogoutTestSupport.assertRejected(Reason.BAD_REQUEST, h(LogoutTestSupport.sp(), q + "&SAMLResponse=AAAA"));
    }

    @Test
    public void p1_signatureCoversMessageNameAndValue() {
        final ServiceProvider sp = LogoutTestSupport.sp();
        // IdP-signed LogoutResponse recast as a request
        final String resp = LogoutTestSupport.redirectQuery("SAMLResponse", TestIdp.logoutResponseXml("_a5", Names.STATUS_SUCCESS), null,
                TestIdp.IDP_KEY);
        assertEquals(Reason.INVALID_SIGNATURE, h(sp, resp.replace("SAMLResponse=", "SAMLRequest=")).reason());
        // signature of message A grafted on message B
        final String a = req("_a6").signed();
        final String b = req("_a7").nameId("alice@example.com").unsigned();
        final String graft = b + a.substring(a.indexOf("&SigAlg="));
        assertEquals(Reason.INVALID_SIGNATURE, h(sp, graft).reason());
        // wrong key
        assertEquals(Reason.INVALID_SIGNATURE,
                h(sp, LogoutTestSupport.redirectQuery("SAMLRequest", req("_a8").xml(), null, TestIdp.OTHER_KEY)).reason());
    }

    @Test
    public void p1_relayStateRawBytesAreSigned() {
        final ServiceProvider sp = LogoutTestSupport.sp();
        final String q = req("_a9").signed("a b"); // signed over RelayState=a%20b
        assertEquals(Reason.INVALID_SIGNATURE, h(sp, q.replace("RelayState=a%20b", "RelayState=a+b")).reason());
        assertEquals(Reason.INVALID_SIGNATURE, h(sp, q.replace("RelayState=a%20b", "RelayState=a%20c")).reason());
        assertEquals(Reason.INVALID_SIGNATURE, h(sp, q.replace("&RelayState=a%20b", "")).reason());
    }

    @Test
    public void p1_sigAlgPolicy() {
        final ServiceProvider sp = LogoutTestSupport.sp();
        final String q = req("_b1").signed();
        assertEquals(Reason.INVALID_SIGNATURE, h(sp, q.replaceAll("rsa-sha256", "rsa-sha1")).reason());
        assertEquals(Reason.INVALID_SIGNATURE, h(sp, q.replaceAll("rsa-sha256", "none")).reason());
        LogoutTestSupport.assertRejected(Reason.BAD_REQUEST, h(sp, q.substring(0, q.indexOf("&Signature="))));
    }

    @Test
    public void p1_badSignatureIsNeverTreatedAsUnsigned() {
        final ServiceProvider relaxed = LogoutTestSupport.spAcceptingUnsigned();
        final String q = req("_b2").signed();
        assertEquals(Reason.INVALID_SIGNATURE, h(relaxed, q.replaceFirst("Signature=.", "Signature=A")).reason());
        assertEquals(Reason.INVALID_SIGNATURE, h(relaxed, q.replaceFirst("&Signature=.*", "&Signature=")).reason());
        assertEquals(Action.END_SESSION, h(relaxed, req("_b3").unsigned()).action());
    }

    // ---- probe 2: POST binding ----

    private static String signedPost(final String xml) {
        final Document doc = TestIdp.parse(xml);
        TestIdp.sign(doc.getDocumentElement(), TestIdp.IDP_KEY, Names.RSA_SHA256, DIGEST);
        return TestIdp.encode(doc);
    }

    @Test
    public void p2_postSizeCapsAndHardening() {
        final ServiceProvider sp = LogoutTestSupport.sp();
        final int max = sp.config().maxMessageSize();
        final String big = "A".repeat(2 * max + 2000);
        assertEquals(Reason.TOO_LARGE, sp.handleLogoutPost(big, null, null, null, null).reason());
        final String doctype = TestIdp.encode("<!DOCTYPE x [<!ENTITY e \"y\">]>" + req("_c1").xml());
        assertEquals(Reason.MALFORMED, sp.handleLogoutPost(doctype, null, null, null, null).reason());
        // redirect: inflate bomb is capped
        final String bomb = "<a>" + "x".repeat(8 * 1024 * 1024) + "</a>";
        final String q = "SAMLRequest=" + Text.urlEncode(TestIdp.deflate(bomb));
        assertEquals(Reason.TOO_LARGE, h(LogoutTestSupport.spAcceptingUnsigned(), q).reason());
        // redirect: query too long
        assertEquals(Reason.TOO_LARGE, h(sp, "SAMLRequest=" + "A".repeat(2 * max + 5000)).reason());
    }

    @Test
    public void p2_postSignaturePolicy() {
        final ServiceProvider sp = LogoutTestSupport.sp();
        final String xml = TestIdp.logoutRequestXml("_c2", "alice@example.com", null);
        assertEquals(Reason.NOT_SIGNED, sp.handleLogoutPost(TestIdp.encode(xml), null, null, "alice@example.com", null).reason());
        final Document other = TestIdp.parse(xml);
        TestIdp.sign(other.getDocumentElement(), TestIdp.OTHER_KEY, Names.RSA_SHA256, DIGEST);
        assertEquals(Reason.INVALID_SIGNATURE, sp.handleLogoutPost(TestIdp.encode(other), null, null, "alice@example.com", null).reason());
        // signed IdP message for bob embedded in an unsigned outer message for alice (wrapping)
        final String inner = signedPost(TestIdp.logoutRequestXml("_c3", "bob@example.com", null));
        final String innerXml = new String(Base64.getDecoder().decode(inner), StandardCharsets.UTF_8);
        final String wrapped = TestIdp.logoutRequestXml("_c4", "alice@example.com", null)
                .replace("</samlp:LogoutRequest>", "<samlp:Extensions>" + innerXml + "</samlp:Extensions></samlp:LogoutRequest>");
        assertEquals(Reason.NOT_SIGNED, sp.handleLogoutPost(TestIdp.encode(wrapped), null, null, "alice@example.com", null).reason());
    }

    @Test
    public void p2_commentInNameIdDoesNotTruncate() {
        final String xml = TestIdp.logoutRequestXml("_c5", "alice@example.com", null)
                .replace("alice@example.com</saml:NameID>", "alice@example.com<!---->.evil.com</saml:NameID>");
        final LogoutOutcome o = LogoutTestSupport.sp().handleLogoutPost(signedPost(xml), null, null, "alice@example.com", null);
        assertEquals(Action.KEEP_SESSION, o.action(), o.toString());
    }

    // ---- probe 3/4: replay and session matching ----

    @Test
    public void p3_idIsRegisteredOnlyAfterFullValidation() {
        final ServiceProvider sp = LogoutTestSupport.sp();
        final LogoutTestSupport.Request bad = req("_d1");
        bad.issuer = "https://evil.example.com";
        assertEquals(Reason.WRONG_ISSUER, h(sp, bad.signed()).reason());
        assertEquals(Action.END_SESSION, h(sp, req("_d1").signed()).action());
        assertEquals(Reason.REPLAYED, h(sp, req("_d1").signed()).reason());
        // unsigned flood cannot pre-burn a signed ID: refused unsigned, so never registered
        final ServiceProvider sp2 = LogoutTestSupport.sp();
        LogoutTestSupport.assertRejected(Reason.NOT_SIGNED, h(sp2, req("_d2").unsigned()));
        assertEquals(Action.END_SESSION, h(sp2, req("_d2").signed()).action());
    }

    @Test
    public void p3_cacheIsAtomicUnderConcurrency() throws Exception {
        final InMemoryReplayCache cache = new InMemoryReplayCache();
        final java.time.Instant exp = java.time.Instant.now().plusSeconds(600);
        final AtomicInteger fresh = new AtomicInteger();
        final ExecutorService ex = Executors.newFixedThreadPool(16);
        final List<Future<?>> fs = new ArrayList<>();
        for (int t = 0; t < 16; t++) {
            fs.add(ex.submit(() -> {
                for (int i = 0; i < 2000; i++) {
                    if (!cache.registerAndCheck("id" + i, exp)) {
                        fresh.incrementAndGet();
                    }
                }
            }));
        }
        for (final Future<?> f : fs) {
            f.get();
        }
        ex.shutdown();
        assertEquals(2000, fresh.get());
    }

    @Test
    public void p4_sessionMatchingEdges() {
        final ServiceProvider sp = LogoutTestSupport.sp();
        final String bob = req("_e1").nameId("bob@example.com").signed();
        assertEquals(Action.KEEP_SESSION, sp.handleLogout("GET", bob, "alice@example.com", "_session1").action());
        assertEquals(Action.KEEP_SESSION, sp.handleLogout("GET", req("_e2").signed(), null, null).action());
        assertEquals(Action.KEEP_SESSION, sp.handleLogout("GET", req("_e3").signed(), "", "_session1").action());
        assertEquals(Action.KEEP_SESSION,
                sp.handleLogout("GET", req("_e4").sessionIndexes("_other").signed(), "alice@example.com", "_session1").action());
        assertEquals(Reason.MALFORMED, h(sp, req("_e5").nameId("").signed()).reason());
        assertEquals(Reason.MALFORMED, h(sp, req("_e6").nameId("  ").signed()).reason());
        assertEquals(Reason.MALFORMED, h(sp, req("_e7").nameId(null).signed()).reason());
    }

    // ---- probe 5: outgoing ----

    @Test
    public void p5_outgoingValuesAreEscapedAndUrlIsFromConfig() {
        final ServiceProvider sp = LogoutTestSupport.sp();
        final String nasty = "a\"><x/>&b'\r\n\t<![CDATA[";
        final LogoutStart s = sp.startLogout(new NameId(nasty, "f\"o", "q\"", "s<"), "_i\"><y/>");
        assertTrue(s.redirectUrl().startsWith(TestIdp.SLO + "?SAMLRequest="), s.redirectUrl());
        final LogoutTestSupport.Sent sent = LogoutTestSupport.sent(s.redirectUrl());
        assertTrue(sent.signatureVerifies(TestIdp.SP_CERT));
        final Document d = sent.document();
        assertEquals(nasty.replace("\r", "\n").replace("\n\n", "\n"),
                LogoutTestSupport.text(d, Names.NS_SAML, "NameID").replace("\r\n", "\n"));
        assertEquals(0, TestIdp.all(d, "", "x").size());
        assertEquals("_i\"><y/>", LogoutTestSupport.text(d, Names.NS_SAMLP, "SessionIndex"));
    }

    @Test
    public void p5_relayStateCannotRedirectOrInjectHeaders() {
        final ServiceProvider sp = LogoutTestSupport.sp();
        final String relay = "https://evil.example.com/\r\nSet-Cookie: x=1&SigAlg=none#frag";
        final LogoutOutcome o = h(sp, req("_f1").signed(relay));
        assertEquals(Action.END_SESSION, o.action());
        assertTrue(o.redirectUrl().startsWith(TestIdp.SLO + "?SAMLResponse="));
        assertFalse(o.redirectUrl().contains("\r") || o.redirectUrl().contains("\n") || o.redirectUrl().contains(" "));
        final LogoutTestSupport.Sent sent = LogoutTestSupport.sent(o.redirectUrl());
        assertEquals(relay, sent.param("RelayState"));
        assertTrue(sent.signatureVerifies(TestIdp.SP_CERT));
        // over-long RelayState is dropped, not echoed
        final LogoutOutcome longRelay = h(sp, req("_f2").signed("r".repeat(513)));
        assertFalse(longRelay.redirectUrl().contains("RelayState="));
    }

    @Test
    public void p5_logLinesCannotBeForged() {
        final ServiceProvider sp = LogoutTestSupport.sp();
        for (final String evil : new String[] { "x&#10;[ERROR] forged", "x&#13;&#10;INFO y", "x&#x85;z", "x&#x2028;z" }) {
            final String xml = req("_g1").xml().replace("Destination=\"" + TestIdp.SLS + "\"", "Destination=\"" + evil + "\"");
            final LogoutOutcome o = h(sp, LogoutTestSupport.redirectQuery("SAMLRequest", xml, null, TestIdp.IDP_KEY));
            assertEquals(Reason.WRONG_DESTINATION, o.reason(), o.toString());
            assertFalse(o.detail().matches("(?s).*[\\p{Cntrl}\u0085  ].*"), o.detail());
            final String xml2 = req("_g2").xml().replace("<saml:Issuer>" + TestIdp.IDP, "<saml:Issuer>" + evil);
            final LogoutOutcome o2 = h(sp, LogoutTestSupport.redirectQuery("SAMLRequest", xml2, null, TestIdp.IDP_KEY));
            assertEquals(Reason.WRONG_ISSUER, o2.reason(), o2.toString());
            assertFalse(o2.detail().matches("(?s).*[\\p{Cntrl}\u0085  ].*"), o2.detail());
        }
    }

    // ---- probe 6: shared instance ----

    @Test
    public void p6_sharedServiceProviderIsThreadSafe() throws Exception {
        final ServiceProvider sp = LogoutTestSupport.sp();
        final ExecutorService ex = Executors.newFixedThreadPool(16);
        final List<Callable<Integer>> jobs = new ArrayList<>();
        for (int t = 0; t < 16; t++) {
            final int tt = t;
            jobs.add(() -> {
                int ok = 0;
                for (int i = 0; i < 60; i++) {
                    final String id = "_t" + tt + "_" + i;
                    if (sp.handleLogout("GET", req(id).signed(), LogoutTestSupport.USER, LogoutTestSupport.INDEX)
                            .action() == Action.END_SESSION) {
                        ok++;
                    }
                    final LogoutOutcome p = sp.handleLogoutPost(signedPost(TestIdp.logoutRequestXml(id + "p", "alice@example.com", null)),
                            null, null, "alice@example.com", null);
                    if (p.action() == Action.END_SESSION) {
                        ok++;
                    }
                    assertNotNull(sp.startLogin().redirectUrl());
                }
                return ok;
            });
        }
        int total = 0;
        for (final Future<Integer> f : ex.invokeAll(jobs)) {
            total += f.get();
        }
        ex.shutdown();
        assertEquals(16 * 60 * 2, total);
    }
}
