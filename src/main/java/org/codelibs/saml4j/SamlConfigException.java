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
 * Thrown when a configuration is incomplete, has a value that cannot be parsed, or asks for something the library
 * refuses to do. A configuration is never repaired silently.
 */
public class SamlConfigException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Creates an exception.
     *
     * @param message the message, which names the offending key
     */
    public SamlConfigException(final String message) {
        super(message);
    }

    /**
     * Creates an exception.
     *
     * @param message the message, which names the offending key
     * @param cause the cause
     */
    public SamlConfigException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
