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

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.codelibs.saml4j.internal.Names;
import org.junit.jupiter.api.Test;

public class SamlConfigTest {

    private static final String[] REQUIRED =
            { "idp.entityid", "idp.single_sign_on_service.url", "idp.x509cert", "sp.entityid", "sp.assertion_consumer_service.url" };

    private static final String[] BOOLEANS = { "security.authnrequest_signed", "security.want_messages_signed",
            "security.want_assertions_signed", "security.want_assertions_encrypted", "security.want_logout_signed",
            "security.allow_deprecated_alg", "security.allow_rsa_1_5" };

    private static Map<String, String> minimal() {
        final Map<String, String> m = new HashMap<>();
        m.put("idp.entityid", TestIdp.IDP);
        m.put("idp.single_sign_on_service.url", TestIdp.SSO);
        m.put("idp.x509cert", TestIdp.pem("idp"));
        m.put("sp.entityid", TestIdp.SP);
        m.put("sp.assertion_consumer_service.url", TestIdp.ACS);
        return m;
    }

    private static Map<String, String> complete() {
        final Map<String, String> m = minimal();
        m.put("idp.single_logout_service.url", TestIdp.SLO);
        m.put("sp.single_logout_service.url", TestIdp.SLS);
        m.put("sp.nameidformat", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        m.put("sp.x509cert", TestIdp.pem("sp"));
        m.put("sp.privatekey", TestIdp.keyPem("sp"));
        m.put("security.authnrequest_signed", "true");
        m.put("security.want_messages_signed", "true");
        m.put("security.want_assertions_signed", "true");
        m.put("security.want_assertions_encrypted", "true");
        m.put("security.want_logout_signed", "false");
        m.put("security.allow_deprecated_alg", "true");
        m.put("security.allow_rsa_1_5", "true");
        m.put("security.clock_drift", "30");
        m.put("security.max_message_size", "2048");
        m.put("security.requested_authncontext", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
        m.put("security.requested_authncontextcomparison", "minimum");
        m.put("security.signature_algorithm", Names.RSA_SHA512);
        m.put("strict", "true");
        m.put("debug", "false");
        return m;
    }

    private static SamlConfigException refused(final Map<String, String> m) {
        return assertThrows(SamlConfigException.class, () -> SamlConfig.fromMap(m));
    }

    private static String stripHeaders(final String pem) {
        return pem.replaceAll("-----(BEGIN|END) [A-Z ]+-----", "").trim();
    }

    private static String body(final String pem) {
        return stripHeaders(pem).replaceAll("\\s", "");
    }

    // ---- building --------------------------------------------------------------------------------------------------

    @Test
    public void testCompleteMapBuilds() throws Exception {
        final SamlConfig c = SamlConfig.fromMap(complete());
        assertEquals(TestIdp.IDP, c.idpEntityId());
        assertEquals(TestIdp.SSO, c.idpSingleSignOnServiceUrl());
        assertEquals(TestIdp.SLO, c.idpSingleLogoutServiceUrl());
        assertEquals(1, c.idpCertificates().size());
        assertEquals(TestIdp.IDP_CERT, c.idpCertificates().get(0));
        assertEquals(TestIdp.SP, c.spEntityId());
        assertEquals(TestIdp.ACS, c.assertionConsumerServiceUrl());
        assertEquals(TestIdp.SLS, c.singleLogoutServiceUrl());
        assertEquals("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", c.nameIdFormat());
        assertEquals(TestIdp.SP_CERT, c.spCertificate());
        assertEquals(TestIdp.SP_KEY, c.spPrivateKey());
        assertTrue(c.authnRequestSigned());
        assertTrue(c.wantMessagesSigned());
        assertTrue(c.wantAssertionsSigned());
        assertTrue(c.wantAssertionsEncrypted());
        assertFalse(c.wantLogoutSigned());
        assertTrue(c.allowDeprecatedAlg());
        assertTrue(c.allowRsa15());
        assertEquals(30, c.clockDriftSeconds());
        assertEquals(2048, c.maxMessageSize());
        assertEquals("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", c.requestedAuthnContext());
        assertEquals("minimum", c.requestedAuthnContextComparison());
        assertEquals(Names.RSA_SHA512, c.signatureAlgorithm());
    }

    @Test
    public void testMinimalMapUsesDefaults() {
        final SamlConfig c = SamlConfig.fromMap(minimal());
        assertTrue(c.wantLogoutSigned());
        assertFalse(c.allowDeprecatedAlg());
        assertFalse(c.allowRsa15());
        assertFalse(c.authnRequestSigned());
        assertFalse(c.wantMessagesSigned());
        assertFalse(c.wantAssertionsSigned());
        assertFalse(c.wantAssertionsEncrypted());
        assertEquals(120, c.clockDriftSeconds());
        assertEquals(1048576, c.maxMessageSize());
        assertEquals("exact", c.requestedAuthnContextComparison());
        assertEquals(Names.RSA_SHA256, c.signatureAlgorithm());
        assertEquals(Names.NAMEID_UNSPECIFIED, c.nameIdFormat());
        assertNull(c.idpSingleLogoutServiceUrl());
        assertNull(c.singleLogoutServiceUrl());
        assertNull(c.spCertificate());
        assertNull(c.spPrivateKey());
        assertNull(c.requestedAuthnContext());
        assertNotNull(c.clock());
    }

    @Test
    public void testBuilderDefaultsMatchMapDefaults() {
        final SamlConfig c = TestIdp.config().build();
        assertTrue(c.wantLogoutSigned());
        assertFalse(c.allowDeprecatedAlg());
        assertFalse(c.allowRsa15());
        assertEquals(120, c.clockDriftSeconds());
        assertEquals(1048576, c.maxMessageSize());
    }

    @Test
    public void testCertificateWithoutHeadersAndWithLineBreaks() throws Exception {
        final String body = body(TestIdp.pem("idp"));
        final String[] variants = { body, //
                stripHeaders(TestIdp.pem("idp")), //
                stripHeaders(TestIdp.pem("idp")).replace("\n", "\r\n"), //
                body.replaceAll("(.{40})", "$1\n"), //
                "  " + body.substring(0, 100) + "\n\t" + body.substring(100) + "  ", //
                TestIdp.pem("idp").replace("\n", "\r\n") };
        for (final String v : variants) {
            final Map<String, String> m = minimal();
            m.put("idp.x509cert", v);
            assertEquals(TestIdp.IDP_CERT, SamlConfig.fromMap(m).idpCertificates().get(0), v);
        }
    }

    @Test
    public void testPrivateKeyWithAndWithoutHeaders() {
        for (final String pem : new String[] { TestIdp.keyPem("sp"), body(TestIdp.keyPem("sp")), stripHeaders(TestIdp.keyPem("sp")) }) {
            final Map<String, String> m = minimal();
            m.put("sp.privatekey", pem);
            assertEquals(TestIdp.SP_KEY, SamlConfig.fromMap(m).spPrivateKey());
        }
    }

    @Test
    public void testValuesAreTrimmed() {
        final Map<String, String> m = minimal();
        m.put("idp.entityid", "  " + TestIdp.IDP + "\n");
        m.put("security.clock_drift", " 15 ");
        final SamlConfig c = SamlConfig.fromMap(m);
        assertEquals(TestIdp.IDP, c.idpEntityId());
        assertEquals(15, c.clockDriftSeconds());
    }

    // ---- required keys ---------------------------------------------------------------------------------------------

    @Test
    public void testEachRequiredKeyMissingIsNamed() {
        for (final String key : REQUIRED) {
            final Map<String, String> m = minimal();
            m.remove(key);
            final SamlConfigException e = refused(m);
            assertTrue(e.getMessage().contains(key), key + " -> " + e.getMessage());
        }
    }

    @Test
    public void testBlankValueCountsAsAbsent() {
        for (final String key : REQUIRED) {
            for (final String blank : new String[] { "", " ", "\n\t " }) {
                final Map<String, String> m = minimal();
                m.put(key, blank);
                final SamlConfigException e = refused(m);
                assertTrue(e.getMessage().contains(key), key + " -> " + e.getMessage());
            }
        }
    }

    @Test
    public void testNullValueCountsAsAbsent() {
        final Map<String, String> m = minimal();
        m.put("sp.entityid", null);
        assertTrue(refused(m).getMessage().contains("sp.entityid"));
    }

    @Test
    public void testBlankOptionalValueUsesDefault() {
        final Map<String, String> m = minimal();
        m.put("security.clock_drift", "");
        m.put("security.want_logout_signed", " ");
        m.put("security.requested_authncontextcomparison", "");
        m.put("security.signature_algorithm", "");
        m.put("sp.nameidformat", "");
        m.put("strict", "");
        final SamlConfig c = SamlConfig.fromMap(m);
        assertEquals(120, c.clockDriftSeconds());
        assertTrue(c.wantLogoutSigned());
        assertEquals("exact", c.requestedAuthnContextComparison());
        assertEquals(Names.RSA_SHA256, c.signatureAlgorithm());
        assertEquals(Names.NAMEID_UNSPECIFIED, c.nameIdFormat());
    }

    // ---- unknown and removed keys ----------------------------------------------------------------------------------

    @Test
    public void testUnknownKeyIsListed() {
        final Map<String, String> m = minimal();
        m.put("security.something_new", "1");
        final SamlConfigException e = refused(m);
        assertTrue(e.getMessage().contains("security.something_new"), e.getMessage());
    }

    @Test
    public void testAllUnknownKeysAreListed() {
        final Map<String, String> m = minimal();
        m.put("zzz.second", "1");
        m.put("aaa.first", "1");
        final String message = refused(m).getMessage();
        assertTrue(message.contains("aaa.first") && message.contains("zzz.second"), message);
        assertTrue(message.indexOf("aaa.first") < message.indexOf("zzz.second"), message);
    }

    @Test
    public void testUnknownKeyWithBlankValueIsStillRefused() {
        final Map<String, String> m = minimal();
        m.put("unknown.key", "");
        assertTrue(refused(m).getMessage().contains("unknown.key"));
    }

    @Test
    public void testKeysAreCaseSensitive() {
        final Map<String, String> m = minimal();
        m.put("IDP.ENTITYID", TestIdp.IDP);
        assertTrue(refused(m).getMessage().contains("IDP.ENTITYID"));
    }

    @Test
    public void testRemovedKeysAreRefused() {
        final String[] removed = { "idp.certfingerprint", "idp.certfingerprint_algorithm", "security.reject_deprecated_alg",
                "keystore.alias", "keystore.path", "compress.request", "compress.response", "security.signmetadata",
                "security.want_nameid_encrypted", "idp.x509cert.1" };
        for (final String key : removed) {
            final Map<String, String> m = minimal();
            m.put(key, "true");
            final SamlConfigException e = refused(m);
            assertTrue(e.getMessage().contains(key), key + " -> " + e.getMessage());
        }
    }

    @Test
    public void testMultiPrefixWithoutIndexIsUnknown() {
        final Map<String, String> m = minimal();
        m.put("idp.x509certMulti.", TestIdp.pem("other"));
        assertTrue(refused(m).getMessage().contains("idp.x509certMulti."));
    }

    // ---- strict and debug ------------------------------------------------------------------------------------------

    @Test
    public void testStrictTrueIsAccepted() {
        for (final String v : new String[] { "true", "TRUE", "True" }) {
            final Map<String, String> m = minimal();
            m.put("strict", v);
            assertDoesNotThrow(() -> SamlConfig.fromMap(m));
        }
    }

    @Test
    public void testStrictOtherThanTrueIsRefused() {
        for (final String v : new String[] { "false", "FALSE", "yes", "1", "0", "off" }) {
            final Map<String, String> m = minimal();
            m.put("strict", v);
            assertTrue(refused(m).getMessage().contains("strict"), v);
        }
    }

    @Test
    public void testDebugIsIgnored() {
        for (final String v : new String[] { "true", "false", "yes", "garbage" }) {
            final Map<String, String> m = minimal();
            m.put("debug", v);
            assertDoesNotThrow(() -> SamlConfig.fromMap(m), v);
        }
    }

    // ---- booleans --------------------------------------------------------------------------------------------------

    @Test
    public void testBooleanSpellingsOtherThanTrueFalseAreRefused() {
        for (final String key : BOOLEANS) {
            for (final String v : new String[] { "yes", "no", "1", "0", "on", "off", "t", "y", "truee", "null" }) {
                final Map<String, String> m = complete();
                m.put(key, v);
                final SamlConfigException e = refused(m);
                assertTrue(e.getMessage().contains(key), key + "=" + v + " -> " + e.getMessage());
            }
        }
    }

    @Test
    public void testBooleanIsCaseInsensitive() {
        final Map<String, String> m = minimal();
        m.put("security.want_messages_signed", "TRUE");
        m.put("security.want_assertions_signed", "True");
        m.put("security.want_logout_signed", "FALSE");
        final SamlConfig c = SamlConfig.fromMap(m);
        assertTrue(c.wantMessagesSigned());
        assertTrue(c.wantAssertionsSigned());
        assertFalse(c.wantLogoutSigned());
    }

    // ---- integers --------------------------------------------------------------------------------------------------

    @Test
    public void testClockDriftBounds() {
        for (final String v : new String[] { "0", "1", "600" }) {
            final Map<String, String> m = minimal();
            m.put("security.clock_drift", v);
            assertEquals(Integer.parseInt(v), SamlConfig.fromMap(m).clockDriftSeconds());
        }
        for (final String v : new String[] { "-1", "601", "2147483647", "-2147483648" }) {
            final Map<String, String> m = minimal();
            m.put("security.clock_drift", v);
            assertTrue(refused(m).getMessage().contains("security.clock_drift"), v);
        }
    }

    @Test
    public void testMaxMessageSizeBounds() {
        for (final String v : new String[] { "1024", "1048576", "16777216" }) {
            final Map<String, String> m = minimal();
            m.put("security.max_message_size", v);
            assertEquals(Integer.parseInt(v), SamlConfig.fromMap(m).maxMessageSize());
        }
        for (final String v : new String[] { "0", "-1", "1023", "16777217", "2147483647" }) {
            final Map<String, String> m = minimal();
            m.put("security.max_message_size", v);
            assertTrue(refused(m).getMessage().contains("security.max_message_size"), v);
        }
    }

    @Test
    public void testIntegersThatAreNotNumbers() {
        for (final String key : new String[] { "security.clock_drift", "security.max_message_size" }) {
            for (final String v : new String[] { "abc", "1.5", "1e3", "12 34", "0x10", "99999999999", "-99999999999" }) {
                final Map<String, String> m = minimal();
                m.put(key, v);
                final SamlConfigException e = refused(m);
                assertTrue(e.getMessage().contains(key), key + "=" + v + " -> " + e.getMessage());
            }
        }
    }

    @Test
    public void testIntegersWrittenWithNonAsciiDigitsAreRefused() {
        final Map<String, String> m = minimal();
        m.put("security.clock_drift", "\uff11\uff12\uff10");
        assertTrue(refused(m).getMessage().contains("security.clock_drift"));
    }

    @Test
    public void testBuilderBounds() {
        assertThrows(SamlConfigException.class, () -> TestIdp.config().clockDriftSeconds(-1).build());
        assertThrows(SamlConfigException.class, () -> TestIdp.config().clockDriftSeconds(601).build());
        assertThrows(SamlConfigException.class, () -> TestIdp.config().maxMessageSize(1023).build());
        assertThrows(SamlConfigException.class, () -> TestIdp.config().maxMessageSize(16 * 1024 * 1024 + 1).build());
        assertEquals(0, TestIdp.config().clockDriftSeconds(0).build().clockDriftSeconds());
    }

    // ---- certificates ----------------------------------------------------------------------------------------------

    @Test
    public void testMultiCertificatesAreAdded() {
        final Map<String, String> m = minimal();
        m.put("idp.x509certMulti.1", TestIdp.pem("other"));
        m.put("idp.x509certMulti.2", body(TestIdp.pem("sp")));
        final List<X509Certificate> certs = SamlConfig.fromMap(m).idpCertificates();
        assertEquals(3, certs.size());
        assertTrue(certs.contains(TestIdp.IDP_CERT));
        assertTrue(certs.contains(TestIdp.OTHER_CERT));
        assertTrue(certs.contains(TestIdp.SP_CERT));
    }

    @Test
    public void testMultiCertificateWithBlankValueIsSkipped() {
        final Map<String, String> m = minimal();
        m.put("idp.x509certMulti.1", "  ");
        assertEquals(1, SamlConfig.fromMap(m).idpCertificates().size());
    }

    @Test
    public void testBadCertificateIsRefusedAndNamed() {
        final String[] bad = { "not a certificate", "AAAA", body(TestIdp.pem("idp")).substring(0, 200), "!!!!",
                "-----BEGIN CERTIFICATE-----", TestIdp.keyPem("sp") };
        for (final String v : bad) {
            for (final String key : new String[] { "idp.x509cert", "idp.x509certMulti.1", "idp.x509certMulti.2", "sp.x509cert" }) {
                final Map<String, String> m = minimal();
                if (key.startsWith("idp.x509certMulti")) {
                    m.put("idp.x509certMulti.1", TestIdp.pem("other"));
                }
                m.put(key, v);
                final SamlConfigException e = refused(m);
                assertTrue(e.getMessage().contains(key), key + " -> " + e.getMessage());
            }
        }
    }

    @Test
    public void testBuilderRefusesNullCertificate() {
        assertThrows(SamlConfigException.class, () -> TestIdp.config().addIdpCertificate(null).build());
    }

    @Test
    public void testNoIdpCertificateIsRefused() {
        final SamlConfigException e = assertThrows(SamlConfigException.class,
                () -> SamlConfig.builder()
                        .idpEntityId(TestIdp.IDP)
                        .idpSingleSignOnServiceUrl(TestIdp.SSO)
                        .spEntityId(TestIdp.SP)
                        .assertionConsumerServiceUrl(TestIdp.ACS)
                        .build());
        assertTrue(e.getMessage().contains("idp.x509cert"), e.getMessage());
    }

    // ---- single logout ---------------------------------------------------------------------------------------------

    @Test
    public void testIdpLogoutUrlWithoutServiceProviderUrl() {
        final Map<String, String> m = minimal();
        m.put("idp.single_logout_service.url", TestIdp.SLO);
        final String message = refused(m).getMessage();
        assertTrue(message.contains("idp.single_logout_service.url") && message.contains("sp.single_logout_service.url"), message);
    }

    @Test
    public void testServiceProviderLogoutUrlWithoutIdpUrl() {
        final Map<String, String> m = minimal();
        m.put("sp.single_logout_service.url", TestIdp.SLS);
        final String message = refused(m).getMessage();
        assertTrue(message.contains("idp.single_logout_service.url") && message.contains("sp.single_logout_service.url"), message);
    }

    @Test
    public void testBothLogoutUrlsAreAccepted() {
        final Map<String, String> m = minimal();
        m.put("idp.single_logout_service.url", TestIdp.SLO);
        m.put("sp.single_logout_service.url", TestIdp.SLS);
        final SamlConfig c = SamlConfig.fromMap(m);
        assertEquals(TestIdp.SLO, c.idpSingleLogoutServiceUrl());
        assertEquals(TestIdp.SLS, c.singleLogoutServiceUrl());
    }

    // ---- key requirements ------------------------------------------------------------------------------------------

    @Test
    public void testSignedAuthnRequestNeedsPrivateKey() {
        final Map<String, String> m = minimal();
        m.put("security.authnrequest_signed", "true");
        assertTrue(refused(m).getMessage().contains("sp.privatekey"));
        m.put("sp.privatekey", TestIdp.keyPem("sp"));
        assertTrue(SamlConfig.fromMap(m).authnRequestSigned());
    }

    @Test
    public void testEncryptedAssertionsNeedPrivateKey() {
        final Map<String, String> m = minimal();
        m.put("security.want_assertions_encrypted", "true");
        assertTrue(refused(m).getMessage().contains("sp.privatekey"));
        m.put("sp.privatekey", TestIdp.keyPem("sp"));
        assertTrue(SamlConfig.fromMap(m).wantAssertionsEncrypted());
    }

    @Test
    public void testRsa15NeedsPrivateKey() {
        final Map<String, String> m = minimal();
        m.put("security.allow_rsa_1_5", "true");
        assertTrue(refused(m).getMessage().contains("sp.privatekey"));
        m.put("sp.privatekey", TestIdp.keyPem("sp"));
        assertTrue(SamlConfig.fromMap(m).allowRsa15());
    }

    @Test
    public void testFalseFlagsDoNotNeedPrivateKey() {
        final Map<String, String> m = minimal();
        m.put("security.authnrequest_signed", "false");
        m.put("security.want_assertions_encrypted", "false");
        m.put("security.allow_rsa_1_5", "false");
        assertDoesNotThrow(() -> SamlConfig.fromMap(m));
    }

    @Test
    public void testPkcs1PrivateKeyIsRefusedWithClearMessage() {
        final String pkcs1 = "-----BEGIN RSA PRIVATE KEY-----\nTUlJRXBBSUJBQUtDQVFFQXNlY3JldG1hcmtlcg==\n-----END RSA PRIVATE KEY-----\n"; // gitleaks:allow
        final Map<String, String> m = minimal();
        m.put("sp.privatekey", pkcs1);
        final String message = refused(m).getMessage();
        assertTrue(message.contains("sp.privatekey"), message);
        assertTrue(message.contains("PKCS#8"), message);
        assertFalse(message.contains("TUlJRXBB"), message);
    }

    @Test
    public void testEcPrivateKeyHeaderIsRefusedWithClearMessage() {
        final Map<String, String> m = minimal();
        m.put("sp.privatekey", "-----BEGIN EC PRIVATE KEY-----\nQUJD\n-----END EC PRIVATE KEY-----"); // gitleaks:allow
        final String message = refused(m).getMessage();
        assertTrue(message.contains("sp.privatekey") && message.contains("PKCS#8"), message);
    }

    @Test
    public void testMalformedPrivateKeyIsRefused() {
        for (final String v : new String[] { "garbage", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----", "!!!!",
                TestIdp.pem("sp") }) {
            final Map<String, String> m = minimal();
            m.put("sp.privatekey", v);
            assertTrue(refused(m).getMessage().contains("sp.privatekey"), v);
        }
    }

    @Test
    public void testCertificateThatDoesNotBelongToThePrivateKeyIsRefused() {
        final Map<String, String> m = minimal();
        m.put("sp.x509cert", TestIdp.pem("other"));
        m.put("sp.privatekey", TestIdp.keyPem("sp"));
        final SamlConfigException e = refused(m);
        assertTrue(e.getMessage().contains("sp.privatekey") || e.getMessage().contains("sp.x509cert"), e.getMessage());
    }

    @Test
    public void testBuilderRefusesCertificateThatDoesNotBelongToThePrivateKey() {
        assertThrows(SamlConfigException.class,
                () -> TestIdp.config().spCertificate(TestIdp.OTHER_CERT).spPrivateKey(TestIdp.SP_KEY).build());
    }

    // ---- URLs ------------------------------------------------------------------------------------------------------

    @Test
    public void testUrlsThatAreNotHttpWithAHostAreRefused() {
        final String[] bad =
                { "javascript:alert(1)", "/sso", "sso", "//idp.example.com/sso", "ftp://idp.example.com/sso", "file:///etc/passwd",
                        "https:///sso", "https://", "http:", "https://idp.example.com/a b", "data:text/html,x", "mailto:a@example.com" };
        for (final String key : new String[] { "idp.single_sign_on_service.url", "sp.assertion_consumer_service.url" }) {
            for (final String v : bad) {
                final Map<String, String> m = minimal();
                m.put(key, v);
                final SamlConfigException e = refused(m);
                assertTrue(e.getMessage().contains(key), key + "=" + v + " -> " + e.getMessage());
            }
        }
        for (final String v : bad) {
            final Map<String, String> m = minimal();
            m.put("idp.single_logout_service.url", v);
            m.put("sp.single_logout_service.url", TestIdp.SLS);
            assertTrue(refused(m).getMessage().contains("idp.single_logout_service.url"), v);
            final Map<String, String> n = minimal();
            n.put("idp.single_logout_service.url", TestIdp.SLO);
            n.put("sp.single_logout_service.url", v);
            assertTrue(refused(n).getMessage().contains("sp.single_logout_service.url"), v);
        }
    }

    @Test
    public void testHttpAndHttpsUrlsAreAccepted() {
        for (final String v : new String[] { "http://idp.example.com/sso", "https://idp.example.com:8443/sso?a=b",
                "HTTPS://IDP.EXAMPLE.COM/sso", "https://localhost/sso", "https://10.0.0.1/sso" }) {
            final Map<String, String> m = minimal();
            m.put("idp.single_sign_on_service.url", v);
            assertEquals(v, SamlConfig.fromMap(m).idpSingleSignOnServiceUrl());
        }
    }

    @Test
    public void testBuilderRefusesBlankRequiredValues() {
        assertThrows(SamlConfigException.class, () -> TestIdp.config().idpEntityId(" ").build());
        assertThrows(SamlConfigException.class, () -> TestIdp.config().spEntityId(null).build());
        assertThrows(SamlConfigException.class, () -> TestIdp.config().assertionConsumerServiceUrl(null).build());
        assertThrows(SamlConfigException.class, () -> TestIdp.config().idpSingleSignOnServiceUrl("").build());
    }

    // ---- algorithm and comparison ----------------------------------------------------------------------------------

    @Test
    public void testSignatureAlgorithmAllowList() {
        for (final String v : new String[] { Names.RSA_SHA256, Names.RSA_SHA384, Names.RSA_SHA512 }) {
            final Map<String, String> m = minimal();
            m.put("security.signature_algorithm", v);
            assertEquals(v, SamlConfig.fromMap(m).signatureAlgorithm());
        }
        for (final String v : new String[] { Names.RSA_SHA1, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "rsa-sha256",
                "RSA_SHA256", "none", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256 " + "x" }) {
            final Map<String, String> m = minimal();
            m.put("security.signature_algorithm", v);
            assertTrue(refused(m).getMessage().contains("security.signature_algorithm"), v);
        }
    }

    @Test
    public void testRequestedAuthnContextComparison() {
        for (final String v : new String[] { "exact", "minimum", "maximum", "better" }) {
            final Map<String, String> m = minimal();
            m.put("security.requested_authncontextcomparison", v);
            assertEquals(v, SamlConfig.fromMap(m).requestedAuthnContextComparison());
        }
        for (final String v : new String[] { "EXACT", "Exact", "equal", "at_least", "exact,minimum" }) {
            final Map<String, String> m = minimal();
            m.put("security.requested_authncontextcomparison", v);
            assertTrue(refused(m).getMessage().contains("security.requested_authncontextcomparison"), v);
        }
    }

    @Test
    public void testBuilderRefusesNullAlgorithmWithConfigException() {
        assertThrows(SamlConfigException.class, () -> TestIdp.config().signatureAlgorithm(null).build());
    }

    @Test
    public void testBuilderRefusesNullComparisonWithConfigException() {
        assertThrows(SamlConfigException.class, () -> TestIdp.config().requestedAuthnContextComparison(null).build());
    }

    // ---- immutability and messages ---------------------------------------------------------------------------------

    @Test
    public void testCertificateListCannotBeModified() {
        final SamlConfig c = SamlConfig.fromMap(minimal());
        final List<X509Certificate> certs = c.idpCertificates();
        assertThrows(UnsupportedOperationException.class, () -> certs.add(TestIdp.OTHER_CERT));
        assertThrows(UnsupportedOperationException.class, () -> certs.remove(0));
        assertThrows(UnsupportedOperationException.class, certs::clear);
        assertEquals(1, c.idpCertificates().size());
    }

    @Test
    public void testBuilderChangesAfterBuildDoNotReachTheConfiguration() {
        final SamlConfig.Builder b = TestIdp.config();
        final SamlConfig c = b.build();
        b.addIdpCertificate(TestIdp.OTHER_CERT).idpEntityId("https://changed.example.com/").clockDriftSeconds(5);
        assertEquals(1, c.idpCertificates().size());
        assertEquals(TestIdp.IDP, c.idpEntityId());
        assertEquals(120, c.clockDriftSeconds());
        assertEquals(2, b.build().idpCertificates().size());
    }

    @Test
    public void testChangingTheSourceMapAfterBuildDoesNotReachTheConfiguration() {
        final Map<String, String> m = minimal();
        final SamlConfig c = SamlConfig.fromMap(m);
        m.put("idp.entityid", "https://changed.example.com/");
        m.put("idp.x509certMulti.1", TestIdp.pem("other"));
        assertEquals(TestIdp.IDP, c.idpEntityId());
        assertEquals(1, c.idpCertificates().size());
    }

    @Test
    public void testMessagesNeverContainKeyMaterial() {
        final String marker = "S3CR3TM4RK3R";
        final String keyBody = body(TestIdp.keyPem("sp"));
        final String certBody = body(TestIdp.pem("idp"));
        final String[][] cases = { //
                { "sp.privatekey", "-----BEGIN RSA PRIVATE KEY-----\n" + marker + "\n-----END RSA PRIVATE KEY-----" }, // gitleaks:allow
                { "sp.privatekey", "-----BEGIN PRIVATE KEY-----\n" + marker + "\n-----END PRIVATE KEY-----" }, //
                { "sp.privatekey", keyBody.substring(0, keyBody.length() / 2) + marker }, //
                { "sp.privatekey", TestIdp.pem("sp") }, //
                { "idp.x509cert", marker }, //
                { "idp.x509cert", certBody.substring(0, certBody.length() / 2) + marker }, //
                { "idp.x509cert", TestIdp.keyPem("sp") }, //
                { "idp.x509certMulti.1", marker }, //
                { "sp.x509cert", marker }, //
                { "idp.entityid", " " }, //
                { "idp.single_sign_on_service.url", "javascript:" + marker }, //
                { "sp.assertion_consumer_service.url", "https://host/" + marker + " x" }, //
                { "security.clock_drift", marker }, //
                { "security.want_messages_signed", marker }, //
                { "security.signature_algorithm", marker }, //
                { "security.requested_authncontextcomparison", marker }, //
                { "strict", marker } };
        for (final String[] c : cases) {
            final Map<String, String> m = minimal();
            m.put(c[0], c[1]);
            final SamlConfigException e = refused(m);
            final String message = String.valueOf(e.getMessage());
            assertFalse(message.contains(marker), c[0] + " -> " + message);
            assertFalse(message.contains(keyBody.substring(0, 40)), c[0] + " -> " + message);
            assertFalse(message.contains(certBody.substring(0, 40)), c[0] + " -> " + message);
            for (Throwable t = e.getCause(); t != null; t = t.getCause()) {
                assertFalse(String.valueOf(t.getMessage()).contains(marker), c[0] + " cause -> " + t.getMessage());
            }
        }
    }
}
