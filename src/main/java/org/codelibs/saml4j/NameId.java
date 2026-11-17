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
 * The NameID of a subject.
 *
 * @param value the identifier, never blank
 * @param format the format URI, or {@code null}
 * @param nameQualifier the NameQualifier, or {@code null}
 * @param spNameQualifier the SPNameQualifier, or {@code null}
 */
public record NameId(String value, String format, String nameQualifier, String spNameQualifier) {

    /**
     * Creates a NameID that has only a value.
     *
     * @param value the identifier
     * @return the NameID
     */
    public static NameId of(final String value) {
        return new NameId(value, null, null, null);
    }
}
