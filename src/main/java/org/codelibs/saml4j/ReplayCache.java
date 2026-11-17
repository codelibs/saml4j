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

/**
 * Remembers the IDs of messages that were accepted, so that the same message is not accepted twice.
 */
public interface ReplayCache {

    /**
     * Registers an ID.
     *
     * @param id the message ID
     * @param expiresAt when the message can no longer be accepted, drift included; the entry may be dropped after it
     * @return {@code true} if the ID was already registered and has not expired
     */
    boolean registerAndCheck(String id, Instant expiresAt);
}
