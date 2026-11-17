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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Set;

import org.codelibs.saml4j.LogoutOutcome.Action;
import org.junit.jupiter.api.Test;

/** Logout messages: matching, replay bookkeeping, ordering of the checks, and what goes out. */
public class LogoutHardeningTest {

    /** unsigned logout messages (want_logout_signed=false) share the replay cache with assertion IDs and evict them. */
    @Test
    public void unsignedLogoutFloodDoesNotEvictAssertionIds() {
        final ServiceProvider sp = LogoutTestSupport.spAcceptingUnsigned();
        final String encoded = TestIdp.response().encoded();
        assertInstanceOf(LoginResult.Authenticated.class, sp.finishLogin(encoded, Set.of("_req1")));
        assertEquals(Reason.REPLAYED, assertInstanceOf(LoginResult.Rejected.class, sp.finishLogin(encoded, Set.of("_req1"))).reason());
        for (int i = 0; i < InMemoryReplayCache.DEFAULT_MAX_ENTRIES + 100; i++) {
            final LogoutTestSupport.Request r = new LogoutTestSupport.Request("_flood" + i);
            r.destination = null;
            r.issueInstant = TestIdp.NOW.plusSeconds(120).toString(); // latest expiry the window allows
            sp.handleLogout("GET", r.unsigned(), null, null);
        }
        final LoginResult again = sp.finishLogin(encoded, Set.of("_req1"));
        assertEquals(Reason.REPLAYED, assertInstanceOf(LoginResult.Rejected.class, again, "assertion replay accepted: " + again).reason());
    }

    /** NameID is case-sensitive in SAML; a request for "ALICE" must not end the session of "alice". */
    @Test
    public void nameIdMatchIsCaseSensitive() {
        final String q = new LogoutTestSupport.Request("_c1").nameId("ALICE@EXAMPLE.COM").signed();
        final LogoutOutcome o = LogoutTestSupport.handle(LogoutTestSupport.sp(), q);
        assertEquals(Action.KEEP_SESSION, o.action(), o.toString());
    }

    /** surrounding whitespace in the NameID is significant too. */
    @Test
    public void nameIdMatchIsNotWhitespaceTrimmed() {
        final String q = new LogoutTestSupport.Request("_c2").nameId("  alice@example.com  ").signed();
        final LogoutOutcome o = LogoutTestSupport.handle(LogoutTestSupport.sp(), q);
        assertEquals(Action.KEEP_SESSION, o.action(), o.toString());
    }

    /** a request that names SessionIndex "_other" must not end a session whose index the SP did not record. */
    @Test
    public void unknownSessionIndexDoesNotMatchAnyNamedIndex() {
        final String q = new LogoutTestSupport.Request("_i1").sessionIndexes("_other").signed();
        final LogoutOutcome o = LogoutTestSupport.sp().handleLogout("GET", q, LogoutTestSupport.USER, null);
        assertEquals(Action.KEEP_SESSION, o.action(), o.toString());
    }

    /** with want_logout_signed=true, an unsigned redirect message is refused before its XML is inflated and parsed. */
    @Test
    public void unsignedMessageIsRefusedBeforeParsing() {
        final String q = "SAMLRequest=" + org.codelibs.saml4j.internal.Text.urlEncode(TestIdp.deflate("<not-xml"));
        final LogoutOutcome o = LogoutTestSupport.handle(LogoutTestSupport.sp(), q);
        LogoutTestSupport.assertRejected(Reason.NOT_SIGNED, o);
    }

    /** every character put into an outgoing message must be legal XML 1.0, or the IdP cannot parse the logout request. */
    @Test
    public void outgoingXmlIsAlwaysWellFormed() {
        final LogoutStart s = LogoutTestSupport.sp().startLogout(NameId.of("a￿b"), null);
        TestIdp.parse(LogoutTestSupport.sent(s.redirectUrl()).xml()); // throws if not well-formed
    }

    /** a '+' in RelayState is a space in form encoding; it must come back to the IdP as the same RelayState. */
    @Test
    public void relayStatePlusIsKeptAsSent() {
        // the IdP sent RelayState=a%20b (percent-encoded space) and the SP echoes it: must round-trip
        final String q = new LogoutTestSupport.Request("_r1").signed("a b");
        final LogoutOutcome o = LogoutTestSupport.handle(LogoutTestSupport.sp(), q);
        assertEquals("a b", LogoutTestSupport.sent(o.redirectUrl()).param("RelayState"));
    }

    /** startLogout(null) is a programming error, not an NPE. */
    @Test
    public void startLogoutNullNameIdIsIllegalArgument() {
        assertThrows(IllegalArgumentException.class, () -> LogoutTestSupport.sp().startLogout(null, null));
    }
}
