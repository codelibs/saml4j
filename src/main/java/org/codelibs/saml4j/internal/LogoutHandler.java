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
import java.util.ArrayList;
import java.util.List;

import org.codelibs.saml4j.LogoutOutcome;
import org.codelibs.saml4j.LogoutOutcome.Action;
import org.codelibs.saml4j.Reason;
import org.codelibs.saml4j.ReplayCache;
import org.codelibs.saml4j.SamlConfig;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Handles the logout messages that arrive at the single logout service.
 *
 * <p>A LogoutResponse never ends a session. A LogoutRequest ends the session it names and no other: a request that
 * names another user, or that arrives for a session that did not come from SAML, leaves the session alone.</p>
 */
public final class LogoutHandler {

    private static final int REQUEST_LIFETIME_SECONDS = 300;

    private static final int RELAY_STATE_LIMIT = 512;

    private final SamlConfig config;

    private final ReplayCache replayCache;

    private final Messages messages;

    /**
     * Creates a handler.
     *
     * @param config the configuration
     * @param replayCache the replay cache
     * @param messages the message builder
     */
    public LogoutHandler(final SamlConfig config, final ReplayCache replayCache, final Messages messages) {
        this.config = config;
        this.replayCache = replayCache;
        this.messages = messages;
    }

    /**
     * Handles a message.
     *
     * @param method the HTTP method
     * @param rawQuery the query string as received
     * @param sessionNameId the NameID of the SAML login of the current session, or {@code null}
     * @param sessionIndex the SessionIndex of that login, or {@code null}
     * @return what to do
     */
    public LogoutOutcome handle(final String method, final String rawQuery, final String sessionNameId, final String sessionIndex) {
        try {
            return doHandle(method, rawQuery, sessionNameId, sessionIndex);
        } catch (final Refusal r) {
            return new LogoutOutcome(Action.REJECTED, null, r.reason(), r.getMessage());
        } catch (final RuntimeException e) {
            return new LogoutOutcome(Action.REJECTED, null, Reason.MALFORMED, "the message could not be processed");
        }
    }

    private LogoutOutcome doHandle(final String method, final String rawQuery, final String sessionNameId, final String sessionIndex) {
        if (config.singleLogoutServiceUrl() == null) {
            throw new Refusal(Reason.UNSUPPORTED, "single logout is not configured");
        }
        if (!"GET".equalsIgnoreCase(method)) {
            throw new Refusal(Reason.BAD_REQUEST, "only GET is accepted");
        }
        final RedirectBinding.Query q = RedirectBinding.parse(rawQuery, 2 * config.maxMessageSize() + 4096);
        final boolean request = q.raw("SAMLRequest") != null;
        final boolean response = q.raw("SAMLResponse") != null;
        if (request == response) {
            throw new Refusal(Reason.BAD_REQUEST, "exactly one of SAMLRequest and SAMLResponse is required");
        }
        final String name = request ? "SAMLRequest" : "SAMLResponse";
        final boolean signed = RedirectBinding.verify(q, name, config.idpCertificates(), config.allowDeprecatedAlg());
        if (config.wantLogoutSigned() && !signed) {
            throw new Refusal(Reason.NOT_SIGNED, "the logout message is not signed");
        }
        final Document doc = SafeXml.parse(RedirectBinding.decodeMessage(q, name, config.maxMessageSize()));
        final String relay = q.raw("RelayState") == null ? null : relayState(q.decoded("RelayState"));
        return process(doc, request, signed, relay, sessionNameId, sessionIndex);
    }

    /**
     * Handles a message that arrived by HTTP-POST: the parameters of the form, and an XML signature in the message.
     *
     * @param samlRequest the {@code SAMLRequest} parameter, or {@code null}
     * @param samlResponse the {@code SAMLResponse} parameter, or {@code null}
     * @param relayState the {@code RelayState} parameter, or {@code null}
     * @param sessionNameId the NameID of the SAML login of the current session, or {@code null}
     * @param sessionIndex the SessionIndex of that login, or {@code null}
     * @return what to do
     */
    public LogoutOutcome handlePost(final String samlRequest, final String samlResponse, final String relayState,
            final String sessionNameId, final String sessionIndex) {
        try {
            if (config.singleLogoutServiceUrl() == null) {
                throw new Refusal(Reason.UNSUPPORTED, "single logout is not configured");
            }
            final boolean request = samlRequest != null && !samlRequest.isBlank();
            final boolean response = samlResponse != null && !samlResponse.isBlank();
            if (request == response) {
                throw new Refusal(Reason.BAD_REQUEST, "exactly one of SAMLRequest and SAMLResponse is required");
            }
            final Document doc = SafeXml.parse(SafeXml.base64(request ? samlRequest : samlResponse, config.maxMessageSize()));
            SafeXml.requireUniqueIds(doc);
            final boolean signed =
                    XmlSecurity.verifyEnveloped(doc.getDocumentElement(), config.idpCertificates(), config.allowDeprecatedAlg());
            return process(doc, request, signed, relayState(relayState), sessionNameId, sessionIndex);
        } catch (final Refusal r) {
            return new LogoutOutcome(Action.REJECTED, null, r.reason(), r.getMessage());
        } catch (final RuntimeException e) {
            return new LogoutOutcome(Action.REJECTED, null, Reason.MALFORMED, "the message could not be processed");
        }
    }

    private LogoutOutcome process(final Document doc, final boolean request, final boolean signed, final String relay,
            final String sessionNameId, final String sessionIndex) {
        if (config.wantLogoutSigned() && !signed) {
            throw new Refusal(Reason.NOT_SIGNED, "the logout message is not signed");
        }
        final Element root = doc.getDocumentElement();
        final Instant now = config.clock().instant();
        final int drift = config.clockDriftSeconds();
        if (!"2.0".equals(SafeXml.attr(root, "Version"))) {
            throw new Refusal(Reason.MALFORMED, "unsupported SAML version");
        }
        final String id = SafeXml.attr(root, "ID");
        SafeXml.requireValidId(id);
        final Instant issued = Times.parse(SafeXml.attr(root, "IssueInstant"), "IssueInstant");
        if (issued.minusSeconds(drift).isAfter(now) || !issued.plusSeconds(REQUEST_LIFETIME_SECONDS + drift).isAfter(now)) {
            throw new Refusal(Reason.EXPIRED, "the message was not issued recently");
        }
        final String destination = SafeXml.attr(root, "Destination");
        if (destination == null ? signed : !destination.equals(config.singleLogoutServiceUrl())) {
            throw new Refusal(Reason.WRONG_DESTINATION, "the destination is not this service provider: " + Text.safe(destination));
        }
        final Element issuer = SafeXml.requiredChild(root, Names.NS_SAML, "Issuer");
        final String issuerText = SafeXml.plainText(issuer);
        if (issuerText == null || !config.idpEntityId().equals(issuerText.trim())) {
            throw new Refusal(Reason.WRONG_ISSUER, "the issuer is not the identity provider: " + Text.safe(issuerText));
        }
        return request ? handleRequest(root, relay, id, issued, signed, sessionNameId, sessionIndex, now, drift)
                : handleResponse(root, id, issued, signed, drift);
    }

    private LogoutOutcome handleRequest(final Element root, final String relay, final String id, final Instant issued, final boolean signed,
            final String sessionNameId, final String sessionIndex, final Instant now, final int drift) {
        if (!SafeXml.is(root, Names.NS_SAMLP, "LogoutRequest")) {
            throw new Refusal(Reason.MALFORMED, "the root element is not a LogoutRequest");
        }
        final String noa = SafeXml.attr(root, "NotOnOrAfter");
        if (noa != null) {
            Times.requireNotEnded(Times.parse(noa, "NotOnOrAfter"), now, drift, "the logout request");
        }
        final Element plain = SafeXml.optionalChild(root, Names.NS_SAML, "NameID");
        final Element encrypted = SafeXml.optionalChild(root, Names.NS_SAML, "EncryptedID");
        if (plain != null == (encrypted != null)) {
            throw new Refusal(Reason.MALFORMED, "the logout request must contain exactly one NameID");
        }
        Element nameId = plain;
        if (encrypted != null) {
            nameId = XmlSecurity.decrypt(encrypted, config.spPrivateKey(), config.allowRsa15());
            if (!SafeXml.is(nameId, Names.NS_SAML, "NameID")) {
                throw new Refusal(Reason.MALFORMED, "the decrypted block is not a NameID");
            }
        }
        final String value = SafeXml.plainText(nameId);
        if (value == null || value.isBlank()) {
            throw new Refusal(Reason.MALFORMED, "the NameID is empty");
        }
        final List<String> indexes = new ArrayList<>();
        for (final Element s : SafeXml.children(root, Names.NS_SAMLP, "SessionIndex")) {
            final String text = SafeXml.plainText(s);
            if (text != null) {
                indexes.add(text);
            }
        }
        if (signed && replayCache != null
                && replayCache.registerAndCheck("logout-request:" + id, issued.plusSeconds(REQUEST_LIFETIME_SECONDS + 2L * drift))) {
            throw new Refusal(Reason.REPLAYED, "the logout request was already used");
        }
        final boolean names = sessionNameId != null && sessionNameId.equals(value)
                && (indexes.isEmpty() || sessionIndex != null && indexes.contains(sessionIndex));
        final String redirect = RedirectBinding.build(config.idpSingleLogoutServiceUrl(), "SAMLResponse",
                messages.logoutResponse(Messages.newId(), now, id), relay, config.spPrivateKey(), config.signatureAlgorithm());
        return new LogoutOutcome(names ? Action.END_SESSION : Action.KEEP_SESSION, redirect, null,
                names ? "the logout request names this session" : "the logout request does not name this session");
    }

    private LogoutOutcome handleResponse(final Element root, final String id, final Instant issued, final boolean signed, final int drift) {
        if (!SafeXml.is(root, Names.NS_SAMLP, "LogoutResponse")) {
            throw new Refusal(Reason.MALFORMED, "the root element is not a LogoutResponse");
        }
        final Element status = SafeXml.requiredChild(root, Names.NS_SAMLP, "Status");
        final Element code = SafeXml.requiredChild(status, Names.NS_SAMLP, "StatusCode");
        if (!Names.STATUS_SUCCESS.equals(SafeXml.attr(code, "Value"))) {
            throw new Refusal(Reason.STATUS_NOT_SUCCESS, "the status is not success: " + Text.safe(SafeXml.attr(code, "Value")));
        }
        if (signed && replayCache != null
                && replayCache.registerAndCheck("logout-response:" + id, issued.plusSeconds(REQUEST_LIFETIME_SECONDS + 2L * drift))) {
            throw new Refusal(Reason.REPLAYED, "the logout response was already used");
        }
        return new LogoutOutcome(Action.KEEP_SESSION, null, null, "the logout response was accepted");
    }

    private static String relayState(final String value) {
        return value == null || value.length() > RELAY_STATE_LIMIT ? null : value;
    }
}
