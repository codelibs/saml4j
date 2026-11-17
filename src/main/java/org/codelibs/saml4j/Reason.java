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
 * Why a SAML message was refused. A reason is a fixed code; text taken from the message itself is only ever
 * carried in a sanitized, bounded {@code detail} string next to it.
 */
public enum Reason {
    /** The message could not be decoded, parsed or is structurally unexpected. */
    MALFORMED,
    /** The message is larger or more deeply nested than the library accepts. */
    TOO_LARGE,
    /** The HTTP method or the combination of parameters is not allowed. */
    BAD_REQUEST,
    /** The message carries no acceptable signature, but one is required. */
    NOT_SIGNED,
    /** A signature is present but does not verify, or uses a rejected algorithm. */
    INVALID_SIGNATURE,
    /** The assertion could not be decrypted. */
    DECRYPTION_FAILED,
    /** The status of the message is not success. */
    STATUS_NOT_SUCCESS,
    /** The issuer is not the configured identity provider. */
    WRONG_ISSUER,
    /** The destination or recipient is not an endpoint of this service provider. */
    WRONG_DESTINATION,
    /** The audience does not name this service provider. */
    WRONG_AUDIENCE,
    /** The response does not answer a pending authentication request. */
    WRONG_IN_RESPONSE_TO,
    /** The message is not yet valid or has expired. */
    EXPIRED,
    /** The message was already processed. */
    REPLAYED,
    /** The message uses a feature this library does not support. */
    UNSUPPORTED
}
