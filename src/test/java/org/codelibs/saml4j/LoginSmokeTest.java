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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

public class LoginSmokeTest {

    private static ServiceProvider sp() {
        return ServiceProvider.create(TestIdp.configWithLogout().build());
    }

    @Test
    public void testSignedResponseLogsIn() {
        final TestIdp.ResponseSpec spec = TestIdp.response();
        final LoginResult r = sp().finishLogin(spec.encoded(), Set.of("_req1"));
        final LoginResult.Authenticated a = assertInstanceOf(LoginResult.Authenticated.class, r, r.toString());
        assertEquals("alice@example.com", a.nameId().value());
        assertEquals(List.of("staff", "dev"), a.attributes().get("memberOf"));
        assertEquals("_req1", a.requestId());
        assertEquals("_session1", a.sessionIndex());
    }

    @Test
    public void testSignedAssertionLogsIn() {
        final TestIdp.ResponseSpec spec = TestIdp.response();
        spec.signResponse = false;
        spec.signAssertion = true;
        assertInstanceOf(LoginResult.Authenticated.class, sp().finishLogin(spec.encoded(), Set.of("_req1")));
    }

    @Test
    public void testEncryptedAssertionLogsIn() {
        for (final String mode : new String[] { "cbc", "gcm" }) {
            final TestIdp.ResponseSpec spec = TestIdp.response();
            spec.encryption = mode;
            final LoginResult r = sp().finishLogin(spec.encoded(), Set.of("_req1"));
            assertInstanceOf(LoginResult.Authenticated.class, r, mode + " " + r);
        }
    }

    @Test
    public void testEncryptedAssertionSignedOnItsOwnLogsIn() {
        for (final String mode : new String[] { "cbc", "gcm" }) {
            final TestIdp.ResponseSpec spec = TestIdp.response();
            spec.encryption = mode;
            spec.signResponse = false;
            spec.signAssertion = true;
            final LoginResult r = sp().finishLogin(spec.encoded(), Set.of("_req1"));
            assertInstanceOf(LoginResult.Authenticated.class, r, mode + " " + r);
        }
    }

    @Test
    public void testUnsignedIsRejected() {
        final TestIdp.ResponseSpec spec = TestIdp.response();
        spec.signResponse = false;
        final LoginResult r = sp().finishLogin(spec.encoded(), Set.of("_req1"));
        assertEquals(Reason.NOT_SIGNED, assertInstanceOf(LoginResult.Rejected.class, r).reason());
    }

    @Test
    public void testStartLoginAndMetadata() {
        final LoginStart s = sp().startLogin();
        assertTrue(s.redirectUrl().startsWith(TestIdp.SSO + "?SAMLRequest="));
        assertTrue(sp().metadata().contains(TestIdp.ACS));
    }
}
