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

/**
 * What to do with an incoming logout message.
 *
 * @param action what the caller must do with the local session
 * @param redirectUrl where to send the browser next (the answer to an IdP-initiated logout), or {@code null}
 * @param reason why the message was refused when {@code action} is {@link Action#REJECTED}, otherwise {@code null}
 * @param detail a short, sanitized description for the log; never {@code null}
 */
public record LogoutOutcome(Action action, String redirectUrl, Reason reason, String detail) {

    /** The action to take. */
    public enum Action {
        /** The message names this session: end it. */
        END_SESSION,
        /** The message is valid but does not name this session: keep it. */
        KEEP_SESSION,
        /** The message was refused: change nothing. */
        REJECTED
    }
}
