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
package org.codelibs.saml4j.internal;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;

import org.codelibs.saml4j.Reason;

/**
 * Time handling for assertions and messages.
 */
public final class Times {

    private Times() {
    }

    /**
     * Parses an {@code xs:dateTime}.
     *
     * @param value the value
     * @param what the name used in the refusal
     * @return the instant
     */
    public static Instant parse(final String value, final String what) {
        try {
            return OffsetDateTime.parse(value.trim()).toInstant();
        } catch (final DateTimeParseException | NullPointerException e) {
            throw new Refusal(Reason.MALFORMED, what + " is not a dateTime");
        }
    }

    /**
     * Refuses a point in time that has not been reached yet.
     *
     * @param notBefore the instant
     * @param now the current time
     * @param driftSeconds the tolerated drift
     * @param what the name used in the refusal
     */
    public static void requireStarted(final Instant notBefore, final Instant now, final int driftSeconds, final String what) {
        if (notBefore.minusSeconds(driftSeconds).isAfter(now)) {
            throw new Refusal(Reason.EXPIRED, what + " is not valid yet");
        }
    }

    /**
     * Refuses a point in time that has been passed.
     *
     * @param notOnOrAfter the instant
     * @param now the current time
     * @param driftSeconds the tolerated drift
     * @param what the name used in the refusal
     */
    public static void requireNotEnded(final Instant notOnOrAfter, final Instant now, final int driftSeconds, final String what) {
        if (!notOnOrAfter.plusSeconds(driftSeconds).isAfter(now)) {
            throw new Refusal(Reason.EXPIRED, what + " has expired");
        }
    }
}
