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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.codelibs.saml4j.internal.Refusal;
import org.codelibs.saml4j.internal.SafeXml;
import org.junit.jupiter.api.Test;

public class ConfigHardeningTest {

    private static Map<String, String> minimal() {
        final Map<String, String> m = new HashMap<>();
        m.put("idp.entityid", TestIdp.IDP);
        m.put("idp.single_sign_on_service.url", TestIdp.SSO);
        m.put("idp.x509cert", TestIdp.pem("idp"));
        m.put("sp.entityid", TestIdp.SP);
        m.put("sp.assertion_consumer_service.url", TestIdp.ACS);
        return m;
    }

    @Test
    public void linesOfAPastedSecretAreNotNamedInTheError() {
        // java.util.Properties splits a PEM written without line continuations: each body line becomes a key
        final Map<String, String> m = minimal();
        final String[] lines = TestIdp.keyPem("sp").split("\\R");
        for (final String line : lines) {
            m.put(line, "");
        }
        final String message = assertThrows(SamlConfigException.class, () -> SamlConfig.fromMap(m)).getMessage();
        for (final String line : lines) {
            if (line.length() > 8 && !line.startsWith("-----")) {
                assertFalse(message.contains(line), "a line of the key is in the message");
            }
        }
        assertTrue(message.contains("more"), message);
    }

    @Test
    public void aMistypedKeyIsNamed() {
        final Map<String, String> m = minimal();
        m.put("security.want_messages_signd", "true");
        assertTrue(
                assertThrows(SamlConfigException.class, () -> SamlConfig.fromMap(m)).getMessage().contains("security.want_messages_signd"));
    }

    @Test
    public void nullClockIsRefused() {
        assertThrows(SamlConfigException.class, () -> TestIdp.config().clock(null).build());
        assertThrows(IllegalArgumentException.class, () -> new InMemoryReplayCache(10, null));
    }

    @Test
    public void nullArgumentsAreIllegalArguments() {
        assertThrows(IllegalArgumentException.class, () -> ServiceProvider.create(null));
        assertThrows(IllegalArgumentException.class, () -> ServiceProvider.metadataOf(null));
        assertThrows(IllegalArgumentException.class, () -> new InMemoryReplayCache().registerAndCheck(null, Instant.now()));
        assertThrows(IllegalArgumentException.class, () -> new InMemoryReplayCache().registerAndCheck("_a", null));
    }

    @Test
    public void urlWithAFragmentIsRefused() {
        final Map<String, String> m = minimal();
        m.put("idp.single_sign_on_service.url", TestIdp.SSO + "#frag");
        assertEquals("idp.single_sign_on_service.url must not have a fragment",
                assertThrows(SamlConfigException.class, () -> SamlConfig.fromMap(m)).getMessage());
    }

    @Test
    public void weakIdpKeyIsRefused() {
        final Map<String, String> m = minimal();
        m.put("idp.x509cert", TestIdp.pem("weak"));
        assertEquals("idp.x509cert must be an RSA key of at least 2048 bits",
                assertThrows(SamlConfigException.class, () -> SamlConfig.fromMap(m)).getMessage());
    }

    @Test
    public void documentWithMoreMarkupThanAnyMessageNeedsIsRefusedBeforeItIsParsed() {
        final String xml = "<r>" + "<a/>".repeat(250_000) + "</r>";
        final Refusal r = assertThrows(Refusal.class, () -> SafeXml.parse(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        assertEquals(Reason.TOO_LARGE, r.reason());
    }
}
