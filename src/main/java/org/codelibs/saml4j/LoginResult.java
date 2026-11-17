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

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * The outcome of {@link ServiceProvider#finishLogin}. A hostile or broken message is a {@link Rejected}, never an
 * exception.
 */
public sealed

interface LoginResult permits LoginResult.Authenticated, LoginResult.Rejected {

    /**
     * A login that was accepted. Every value comes from the part of the response that was verified.
     *
     * @param nameId the subject
     * @param sessionIndex the SessionIndex of the authentication, or {@code null}
     * @param sessionNotOnOrAfter when the IdP session ends, or {@code null}
     * @param attributes the attributes, in document order; values of an attribute that appears more than once are merged, and a value that
     *        is not plain text (it has an element inside) is left out
     * @param requestId the pending request ID the response answered
     */
    record Authenticated(NameId nameId, String sessionIndex, Instant sessionNotOnOrAfter, Map<String, List<String>> attributes,
            String requestId) implements LoginResult {
    }

    /**
     * A login that was refused.
     *
     * @param reason the reason code
     * @param detail a short description for the log, stripped of control characters and bounded in length but not escaped for HTML, and it can quote the sender's text; never {@code null}. Do not show it to the user: show the reason code
     */
    record Rejected(Reason reason, String detail) implements LoginResult {
    }
}
