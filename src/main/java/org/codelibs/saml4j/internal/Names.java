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

import java.util.Set;

/**
 * Namespaces and algorithm identifiers. The allow-lists here are the only algorithms the library hands to the XML
 * security library.
 */
public final class Names {

    public static final String NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion";

    public static final String NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol";

    public static final String NS_DS = "http://www.w3.org/2000/09/xmldsig#";

    public static final String NS_XENC = "http://www.w3.org/2001/04/xmlenc#";

    public static final String NS_XENC11 = "http://www.w3.org/2009/xmlenc11#";

    public static final String NS_EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";

    public static final String STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";

    public static final String CM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";

    public static final String BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

    public static final String BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

    public static final String NAMEID_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";

    public static final String RSA_SHA1 = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";

    public static final String RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    public static final String RSA_SHA384 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384";

    public static final String RSA_SHA512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512";

    public static final String SHA1 = "http://www.w3.org/2000/09/xmldsig#sha1";

    /** Signature methods accepted in an XML signature. */
    public static final Set<String> XML_SIGNATURE_METHODS =
            Set.of(RSA_SHA256, RSA_SHA384, RSA_SHA512, "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
                    "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512");

    /** Signature methods accepted only when deprecated algorithms are allowed. */
    public static final Set<String> DEPRECATED_SIGNATURE_METHODS = Set.of(RSA_SHA1);

    /** Digest methods accepted. */
    public static final Set<String> DIGEST_METHODS = Set.of("http://www.w3.org/2001/04/xmlenc#sha256",
            "http://www.w3.org/2001/04/xmldsig-more#sha384", "http://www.w3.org/2001/04/xmlenc#sha512");

    /** Digest methods accepted only when deprecated algorithms are allowed. */
    public static final Set<String> DEPRECATED_DIGEST_METHODS = Set.of(SHA1);

    /** Canonicalization methods accepted (without comments). */
    public static final Set<String> C14N_METHODS = Set.of("http://www.w3.org/2001/10/xml-exc-c14n#",
            "http://www.w3.org/TR/2001/REC-xml-c14n-20010315", "http://www.w3.org/2006/12/xml-c14n11");

    /** The enveloped-signature transform. */
    public static final String ENVELOPED = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";

    /** Content encryption algorithms accepted. */
    public static final Set<String> DATA_ENCRYPTION =
            Set.of("http://www.w3.org/2001/04/xmlenc#aes128-cbc", "http://www.w3.org/2001/04/xmlenc#aes192-cbc",
                    "http://www.w3.org/2001/04/xmlenc#aes256-cbc", "http://www.w3.org/2009/xmlenc11#aes128-gcm",
                    "http://www.w3.org/2009/xmlenc11#aes192-gcm", "http://www.w3.org/2009/xmlenc11#aes256-gcm");

    /** The OAEP key transport algorithms accepted. */
    public static final Set<String> KEY_TRANSPORT_OAEP =
            Set.of("http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p", "http://www.w3.org/2009/xmlenc11#rsa-oaep");

    /** RSA 1.5 key transport, accepted only on request. */
    public static final String KEY_TRANSPORT_RSA15 = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";

    /** Mask generation functions accepted for xenc11 OAEP. */
    public static final Set<String> MGF = Set.of("http://www.w3.org/2009/xmlenc11#mgf1sha1", "http://www.w3.org/2009/xmlenc11#mgf1sha224",
            "http://www.w3.org/2009/xmlenc11#mgf1sha256", "http://www.w3.org/2009/xmlenc11#mgf1sha384",
            "http://www.w3.org/2009/xmlenc11#mgf1sha512");

    private Names() {
    }
}
