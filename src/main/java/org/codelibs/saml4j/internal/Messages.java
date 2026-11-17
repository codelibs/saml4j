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

import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;

import org.codelibs.saml4j.NameId;
import org.codelibs.saml4j.SamlConfig;

/**
 * Builds the messages this service provider sends. Every value is escaped; nothing is substituted into a template.
 */
public final class Messages {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final SamlConfig config;

    /**
     * Creates the builder.
     *
     * @param config the configuration
     */
    public Messages(final SamlConfig config) {
        this.config = config;
    }

    /**
     * Returns a new message ID.
     *
     * @return an ID that is a valid {@code xs:ID} with 128 random bits
     */
    public static String newId() {
        final byte[] b = new byte[16];
        RANDOM.nextBytes(b);
        return "_" + HexFormat.of().formatHex(b);
    }

    private static String instant(final Instant t) {
        return t.truncatedTo(ChronoUnit.SECONDS).toString();
    }

    /**
     * Builds an AuthnRequest.
     *
     * @param id the ID
     * @param now the current time
     * @return the XML
     */
    public String authnRequest(final String id, final Instant now) {
        final StringBuilder sb = new StringBuilder(512);
        sb.append("<samlp:AuthnRequest xmlns:samlp=\"")
                .append(Names.NS_SAMLP)
                .append("\" xmlns:saml=\"")
                .append(Names.NS_SAML)
                .append("\" ID=\"")
                .append(id)
                .append("\" Version=\"2.0\" IssueInstant=\"")
                .append(instant(now))
                .append("\" Destination=\"")
                .append(Text.xml(config.idpSingleSignOnServiceUrl()))
                .append("\" ProtocolBinding=\"")
                .append(Names.BINDING_POST)
                .append("\" AssertionConsumerServiceURL=\"")
                .append(Text.xml(config.assertionConsumerServiceUrl()))
                .append("\">");
        sb.append("<saml:Issuer>").append(Text.xml(config.spEntityId())).append("</saml:Issuer>");
        sb.append("<samlp:NameIDPolicy Format=\"").append(Text.xml(config.nameIdFormat())).append("\" AllowCreate=\"true\"/>");
        if (config.requestedAuthnContext() != null) {
            sb.append("<samlp:RequestedAuthnContext Comparison=\"")
                    .append(config.requestedAuthnContextComparison())
                    .append("\"><saml:AuthnContextClassRef>")
                    .append(Text.xml(config.requestedAuthnContext()))
                    .append("</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>");
        }
        return sb.append("</samlp:AuthnRequest>").toString();
    }

    /**
     * Builds a LogoutRequest.
     *
     * @param id the ID
     * @param now the current time
     * @param nameId the subject
     * @param sessionIndex the session index, or {@code null}
     * @return the XML
     */
    public String logoutRequest(final String id, final Instant now, final NameId nameId, final String sessionIndex) {
        final StringBuilder sb = new StringBuilder(512);
        sb.append("<samlp:LogoutRequest xmlns:samlp=\"")
                .append(Names.NS_SAMLP)
                .append("\" xmlns:saml=\"")
                .append(Names.NS_SAML)
                .append("\" ID=\"")
                .append(id)
                .append("\" Version=\"2.0\" IssueInstant=\"")
                .append(instant(now))
                .append("\" NotOnOrAfter=\"")
                .append(instant(now.plusSeconds(300)))
                .append("\" Destination=\"")
                .append(Text.xml(config.idpSingleLogoutServiceUrl()))
                .append("\">");
        sb.append("<saml:Issuer>").append(Text.xml(config.spEntityId())).append("</saml:Issuer>");
        sb.append("<saml:NameID");
        attribute(sb, "Format", nameId.format());
        attribute(sb, "NameQualifier", nameId.nameQualifier());
        attribute(sb, "SPNameQualifier", nameId.spNameQualifier());
        sb.append('>').append(Text.xml(nameId.value())).append("</saml:NameID>");
        if (sessionIndex != null && !sessionIndex.isEmpty()) {
            sb.append("<samlp:SessionIndex>").append(Text.xml(sessionIndex)).append("</samlp:SessionIndex>");
        }
        return sb.append("</samlp:LogoutRequest>").toString();
    }

    /**
     * Builds a successful LogoutResponse.
     *
     * @param id the ID
     * @param now the current time
     * @param inResponseTo the ID of the LogoutRequest answered
     * @return the XML
     */
    public String logoutResponse(final String id, final Instant now, final String inResponseTo) {
        return "<samlp:LogoutResponse xmlns:samlp=\"" + Names.NS_SAMLP + "\" xmlns:saml=\"" + Names.NS_SAML + "\" ID=\"" + id
                + "\" Version=\"2.0\" IssueInstant=\"" + instant(now) + "\" Destination=\"" + Text.xml(config.idpSingleLogoutServiceUrl())
                + "\" InResponseTo=\"" + Text.xml(inResponseTo) + "\"><saml:Issuer>" + Text.xml(config.spEntityId())
                + "</saml:Issuer><samlp:Status><samlp:StatusCode Value=\"" + Names.STATUS_SUCCESS
                + "\"/></samlp:Status></samlp:LogoutResponse>";
    }

    /**
     * Builds the metadata of this service provider.
     *
     * @return the XML
     */
    public String metadata() {
        final StringBuilder sb = new StringBuilder(1024);
        sb.append("<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" xmlns:ds=\"")
                .append(Names.NS_DS)
                .append("\" entityID=\"")
                .append(Text.xml(config.spEntityId()))
                .append("\"><md:SPSSODescriptor AuthnRequestsSigned=\"")
                .append(config.authnRequestSigned())
                .append("\" WantAssertionsSigned=\"")
                .append(config.wantAssertionsSigned())
                .append("\" protocolSupportEnumeration=\"")
                .append(Names.NS_SAMLP)
                .append("\">");
        if (config.spCertificate() != null) {
            for (final String use : new String[] { "signing", "encryption" }) {
                sb.append("<md:KeyDescriptor use=\"")
                        .append(use)
                        .append("\"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>")
                        .append(certificate(config))
                        .append("</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>");
            }
        }
        if (config.singleLogoutServiceUrl() != null) {
            sb.append("<md:SingleLogoutService Binding=\"")
                    .append(Names.BINDING_REDIRECT)
                    .append("\" Location=\"")
                    .append(Text.xml(config.singleLogoutServiceUrl()))
                    .append("\"/><md:SingleLogoutService Binding=\"")
                    .append(Names.BINDING_POST)
                    .append("\" Location=\"")
                    .append(Text.xml(config.singleLogoutServiceUrl()))
                    .append("\"/>");
        }
        sb.append("<md:NameIDFormat>").append(Text.xml(config.nameIdFormat())).append("</md:NameIDFormat>");
        sb.append("<md:AssertionConsumerService Binding=\"")
                .append(Names.BINDING_POST)
                .append("\" Location=\"")
                .append(Text.xml(config.assertionConsumerServiceUrl()))
                .append("\" index=\"1\" isDefault=\"true\"/>");
        return sb.append("</md:SPSSODescriptor></md:EntityDescriptor>").toString();
    }

    private static String certificate(final SamlConfig config) {
        try {
            return Base64.getEncoder().encodeToString(config.spCertificate().getEncoded());
        } catch (final java.security.cert.CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static void attribute(final StringBuilder sb, final String name, final String value) {
        if (value != null && !value.isEmpty()) {
            sb.append(' ').append(name).append("=\"").append(Text.xml(value)).append('"');
        }
    }
}
