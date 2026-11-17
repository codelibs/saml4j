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

import org.codelibs.saml4j.Reason;

/**
 * Internal control flow: a message was refused. It carries a reason code and a sanitized detail, never a cause taken
 * from the message.
 */
public final class Refusal extends RuntimeException {

    private static final long serialVersionUID = 1L;

    private final Reason reason;

    /**
     * Creates a refusal.
     *
     * @param reason the reason code
     * @param detail a description; message-derived values must already be passed through {@link Text#safe}
     */
    public Refusal(final Reason reason, final String detail) {
        super(detail, null, false, false);
        this.reason = reason;
    }

    /**
     * Returns the reason code.
     *
     * @return the reason code
     */
    public Reason reason() {
        return reason;
    }
}
