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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.codelibs.saml4j.LoginResult;
import org.codelibs.saml4j.NameId;
import org.codelibs.saml4j.Reason;
import org.codelibs.saml4j.ReplayCache;
import org.codelibs.saml4j.SamlConfig;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Validates a SAML Response received at the assertion consumer service.
 *
 * <p>Everything the result reports is read from the {@code Assertion} element this class settled on, and that
 * element is either signed itself or inside a Response whose signature covers it. The document is parsed once, and a
 * request ID the response does not answer is refused before any signature or decryption work is done.</p>
 */
public final class ResponseValidator {

    private final SamlConfig config;

    private final ReplayCache replayCache;

    /**
     * Creates a validator.
     *
     * @param config the configuration
     * @param replayCache the replay cache
     */
    public ResponseValidator(final SamlConfig config, final ReplayCache replayCache) {
        this.config = config;
        this.replayCache = replayCache;
    }

    /**
     * Validates a response.
     *
     * @param samlResponse the {@code SAMLResponse} parameter
     * @param pendingRequestIds the IDs of the AuthnRequests that were sent and not answered yet
     * @return the result
     */
    public LoginResult validate(final String samlResponse, final Set<String> pendingRequestIds) {
        try {
            return doValidate(samlResponse, pendingRequestIds);
        } catch (final Refusal r) {
            return new LoginResult.Rejected(r.reason(), r.getMessage());
        } catch (final RuntimeException e) {
            return new LoginResult.Rejected(Reason.MALFORMED, "the response could not be processed");
        }
    }

    private LoginResult doValidate(final String samlResponse, final Set<String> pending) {
        if (pending == null || pending.isEmpty()) {
            throw new Refusal(Reason.WRONG_IN_RESPONSE_TO, "no authentication request is pending");
        }
        final Document doc = SafeXml.parse(SafeXml.base64(samlResponse, config.maxMessageSize()));
        final Instant now = config.clock().instant();
        final int drift = config.clockDriftSeconds();

        final Element response = doc.getDocumentElement();
        if (!SafeXml.is(response, Names.NS_SAMLP, "Response")) {
            throw new Refusal(Reason.MALFORMED, "the root element is not a Response");
        }
        SafeXml.requireUniqueIds(doc);
        if (!"2.0".equals(SafeXml.attr(response, "Version"))) {
            throw new Refusal(Reason.MALFORMED, "unsupported SAML version");
        }
        final String responseId = SafeXml.attr(response, "ID");
        if (responseId == null || responseId.isEmpty()) {
            throw new Refusal(Reason.MALFORMED, "the Response has no ID");
        }
        final String inResponseTo = SafeXml.attr(response, "InResponseTo");
        if (inResponseTo != null && !pending.contains(inResponseTo)) {
            throw new Refusal(Reason.WRONG_IN_RESPONSE_TO, "the response does not answer a pending request");
        }
        requireDestination(response);
        requireIssuer(SafeXml.optionalChild(response, Names.NS_SAML, "Issuer"));
        requireSuccess(response);

        if (SafeXml.count(doc, Names.NS_SAML, "Assertion") + SafeXml.count(doc, Names.NS_SAML, "EncryptedAssertion") != 1) {
            throw new Refusal(Reason.MALFORMED, "the response must contain exactly one assertion");
        }

        final boolean responseSigned = XmlSecurity.verifyEnveloped(response, config.idpCertificates(), config.allowDeprecatedAlg());
        if (responseSigned && SafeXml.attr(response, "Destination") == null) {
            throw new Refusal(Reason.WRONG_DESTINATION, "a signed response must carry a Destination");
        }
        if (config.wantMessagesSigned() && !responseSigned) {
            throw new Refusal(Reason.NOT_SIGNED, "the response is not signed");
        }

        final Element plain = SafeXml.optionalChild(response, Names.NS_SAML, "Assertion");
        final Element encrypted = SafeXml.optionalChild(response, Names.NS_SAML, "EncryptedAssertion");
        final Element assertion;
        if (plain != null) {
            if (config.wantAssertionsEncrypted()) {
                throw new Refusal(Reason.UNSUPPORTED, "the assertion is not encrypted but encryption is required");
            }
            assertion = plain;
            requireAssertionSignature(assertion, responseSigned);
        } else if (encrypted != null) {
            if (!responseSigned && inResponseTo == null) {
                throw new Refusal(Reason.WRONG_IN_RESPONSE_TO, "the response does not answer a pending request");
            }
            try {
                assertion = decryptAndVerify(encrypted, responseSigned);
            } catch (final Refusal r) {
                // Nothing authenticated the ciphertext, so what became of the plaintext must not tell the sender anything.
                if (responseSigned) {
                    throw r;
                }
                throw new Refusal(Reason.DECRYPTION_FAILED, "the encrypted assertion was not accepted");
            }
        } else {
            throw new Refusal(Reason.MALFORMED, "the Assertion is not a child of the Response");
        }

        return readAssertion(assertion, pending, inResponseTo, now, drift);
    }

    private Element decryptAndVerify(final Element encrypted, final boolean responseSigned) {
        final Element assertion = XmlSecurity.decrypt(encrypted, config.spPrivateKey(), config.allowRsa15());
        final Document decrypted = assertion.getOwnerDocument();
        if (!SafeXml.is(assertion, Names.NS_SAML, "Assertion") || SafeXml.count(decrypted, Names.NS_SAML, "Assertion") != 1
                || SafeXml.count(decrypted, Names.NS_SAML, "EncryptedAssertion") != 0) {
            throw new Refusal(Reason.MALFORMED, "the decrypted block is not a single assertion");
        }
        SafeXml.requireUniqueIds(decrypted);
        requireAssertionSignature(assertion, responseSigned);
        return assertion;
    }

    private void requireAssertionSignature(final Element assertion, final boolean responseSigned) {
        final boolean assertionSigned = XmlSecurity.verifyEnveloped(assertion, config.idpCertificates(), config.allowDeprecatedAlg());
        if (config.wantAssertionsSigned() && !assertionSigned) {
            throw new Refusal(Reason.NOT_SIGNED, "the assertion is not signed");
        }
        if (!responseSigned && !assertionSigned) {
            throw new Refusal(Reason.NOT_SIGNED, "neither the response nor the assertion is signed");
        }
    }

    private LoginResult readAssertion(final Element assertion, final Set<String> pending, final String responseInResponseTo,
            final Instant now, final int drift) {
        if (!"2.0".equals(SafeXml.attr(assertion, "Version"))) {
            throw new Refusal(Reason.MALFORMED, "unsupported SAML version on the assertion");
        }
        final String assertionId = SafeXml.attr(assertion, "ID");
        if (assertionId == null || assertionId.isEmpty()) {
            throw new Refusal(Reason.MALFORMED, "the assertion has no ID");
        }
        final String issued = SafeXml.attr(assertion, "IssueInstant");
        if (issued == null) {
            throw new Refusal(Reason.MALFORMED, "the assertion has no IssueInstant");
        }
        Times.requireStarted(Times.parse(issued, "IssueInstant"), now, drift, "the assertion");
        requireIssuer(SafeXml.requiredChild(assertion, Names.NS_SAML, "Issuer"));

        final Element subject = SafeXml.requiredChild(assertion, Names.NS_SAML, "Subject");
        final NameId nameId = readNameId(subject);

        final Instant[] confirmationEnd = new Instant[1];
        final String requestId = readConfirmation(subject, pending, now, drift, confirmationEnd);
        if (responseInResponseTo != null && !responseInResponseTo.equals(requestId)) {
            throw new Refusal(Reason.WRONG_IN_RESPONSE_TO, "the response and the assertion answer different requests");
        }

        final Instant conditionsEnd = readConditions(SafeXml.requiredChild(assertion, Names.NS_SAML, "Conditions"), now, drift);

        final List<Element> statements = SafeXml.children(assertion, Names.NS_SAML, "AuthnStatement");
        if (statements.size() != 1) {
            throw new Refusal(Reason.MALFORMED, "the assertion must contain exactly one AuthnStatement");
        }
        final Element authn = statements.get(0);
        final String sessionIndex = SafeXml.attr(authn, "SessionIndex");
        final String sessionEnd = SafeXml.attr(authn, "SessionNotOnOrAfter");
        Instant sessionNotOnOrAfter = null;
        if (sessionEnd != null) {
            sessionNotOnOrAfter = Times.parse(sessionEnd, "SessionNotOnOrAfter");
            Times.requireNotEnded(sessionNotOnOrAfter, now, drift, "the session");
        }

        final Map<String, List<String>> attributes = readAttributes(assertion);

        Instant expires = confirmationEnd[0];
        if (conditionsEnd != null && conditionsEnd.isAfter(expires)) {
            expires = conditionsEnd;
        }
        if (replayCache != null && replayCache.registerAndCheck(assertionId, expires.plusSeconds(drift))) {
            throw new Refusal(Reason.REPLAYED, "the assertion was already used");
        }
        return new LoginResult.Authenticated(nameId, sessionIndex, sessionNotOnOrAfter, attributes, requestId);
    }

    private NameId readNameId(final Element subject) {
        final Element plain = SafeXml.optionalChild(subject, Names.NS_SAML, "NameID");
        final Element encrypted = SafeXml.optionalChild(subject, Names.NS_SAML, "EncryptedID");
        if (plain != null == (encrypted != null)) {
            throw new Refusal(Reason.MALFORMED, "the subject must contain exactly one NameID");
        }
        Element element = plain;
        if (encrypted != null) {
            element = XmlSecurity.decrypt(encrypted, config.spPrivateKey(), config.allowRsa15());
            if (!SafeXml.is(element, Names.NS_SAML, "NameID")) {
                throw new Refusal(Reason.MALFORMED, "the decrypted block is not a NameID");
            }
        }
        final String value = SafeXml.plainText(element);
        if (value == null || value.isBlank()) {
            throw new Refusal(Reason.MALFORMED, "the NameID is empty");
        }
        final String spQualifier = SafeXml.attr(element, "SPNameQualifier");
        if (spQualifier != null && !spQualifier.isEmpty() && !config.spEntityId().equals(spQualifier)) {
            throw new Refusal(Reason.WRONG_AUDIENCE, "the NameID is for another service provider: " + Text.safe(spQualifier));
        }
        return new NameId(value, SafeXml.attr(element, "Format"), SafeXml.attr(element, "NameQualifier"),
                SafeXml.attr(element, "SPNameQualifier"));
    }

    private String readConfirmation(final Element subject, final Set<String> pending, final Instant now, final int drift,
            final Instant[] end) {
        Refusal first = null;
        for (final Element sc : SafeXml.children(subject, Names.NS_SAML, "SubjectConfirmation")) {
            if (!Names.CM_BEARER.equals(SafeXml.attr(sc, "Method"))) {
                continue;
            }
            final Element data = SafeXml.optionalChild(sc, Names.NS_SAML, "SubjectConfirmationData");
            if (data == null) {
                continue;
            }
            Refusal problem = null;
            final String recipient = SafeXml.attr(data, "Recipient");
            final String inResponseTo = SafeXml.attr(data, "InResponseTo");
            final String noa = SafeXml.attr(data, "NotOnOrAfter");
            Instant until = null;
            if (!config.assertionConsumerServiceUrl().equals(recipient)) {
                problem = new Refusal(Reason.WRONG_DESTINATION, "the recipient is not this service provider: " + Text.safe(recipient));
            } else if (inResponseTo == null || !pending.contains(inResponseTo)) {
                problem = new Refusal(Reason.WRONG_IN_RESPONSE_TO, "the confirmation does not answer a pending request");
            } else if (noa == null) {
                problem = new Refusal(Reason.MALFORMED, "the confirmation has no NotOnOrAfter");
            } else {
                until = Times.parse(noa, "SubjectConfirmationData NotOnOrAfter");
                final String nb = SafeXml.attr(data, "NotBefore");
                if (!until.plusSeconds(drift).isAfter(now)) {
                    problem = new Refusal(Reason.EXPIRED, "the confirmation has expired");
                } else if (nb != null && Times.parse(nb, "SubjectConfirmationData NotBefore").minusSeconds(drift).isAfter(now)) {
                    problem = new Refusal(Reason.EXPIRED, "the confirmation is not valid yet");
                }
            }
            if (problem == null) {
                end[0] = until;
                return inResponseTo;
            }
            if (first == null) {
                first = problem;
            }
        }
        throw first != null ? first : new Refusal(Reason.WRONG_IN_RESPONSE_TO, "no bearer confirmation answers a pending request");
    }

    private Instant readConditions(final Element conditions, final Instant now, final int drift) {
        final String nb = SafeXml.attr(conditions, "NotBefore");
        if (nb != null) {
            Times.requireStarted(Times.parse(nb, "Conditions NotBefore"), now, drift, "the assertion");
        }
        final String noa = SafeXml.attr(conditions, "NotOnOrAfter");
        Instant end = null;
        if (noa != null) {
            end = Times.parse(noa, "Conditions NotOnOrAfter");
            Times.requireNotEnded(end, now, drift, "the assertion");
        }
        int restrictions = 0;
        for (final Element c : SafeXml.children(conditions)) {
            if (SafeXml.is(c, Names.NS_SAML, "AudienceRestriction")) {
                restrictions++;
                boolean found = false;
                for (final Element a : SafeXml.children(c, Names.NS_SAML, "Audience")) {
                    final String text = SafeXml.plainText(a);
                    if (text != null && config.spEntityId().equals(text.trim())) {
                        found = true;
                    }
                }
                if (!found) {
                    throw new Refusal(Reason.WRONG_AUDIENCE, "the audience does not name this service provider");
                }
            } else if (!SafeXml.is(c, Names.NS_SAML, "OneTimeUse") && !SafeXml.is(c, Names.NS_SAML, "ProxyRestriction")) {
                throw new Refusal(Reason.UNSUPPORTED, "unsupported condition: " + Text.safe(c.getLocalName()));
            }
        }
        if (restrictions == 0) {
            throw new Refusal(Reason.WRONG_AUDIENCE, "the assertion has no audience restriction");
        }
        return end;
    }

    private Map<String, List<String>> readAttributes(final Element assertion) {
        final Map<String, List<String>> map = new LinkedHashMap<>();
        for (final Element statement : SafeXml.children(assertion, Names.NS_SAML, "AttributeStatement")) {
            if (!SafeXml.children(statement, Names.NS_SAML, "EncryptedAttribute").isEmpty()) {
                throw new Refusal(Reason.UNSUPPORTED, "encrypted attributes are not supported");
            }
            for (final Element attribute : SafeXml.children(statement, Names.NS_SAML, "Attribute")) {
                final String name = SafeXml.attr(attribute, "Name");
                if (name == null || name.isEmpty()) {
                    throw new Refusal(Reason.MALFORMED, "an attribute has no name");
                }
                final List<String> values = map.computeIfAbsent(name, k -> new ArrayList<>());
                for (final Element v : SafeXml.children(attribute, Names.NS_SAML, "AttributeValue")) {
                    final String text = SafeXml.plainText(v);
                    if (text != null) {
                        values.add(text);
                    }
                }
            }
        }
        final Map<String, List<String>> copy = new LinkedHashMap<>();
        map.forEach((k, v) -> copy.put(k, List.copyOf(v)));
        return java.util.Collections.unmodifiableMap(copy);
    }

    private void requireDestination(final Element response) {
        final String destination = SafeXml.attr(response, "Destination");
        if (destination != null && !destination.equals(config.assertionConsumerServiceUrl())) {
            throw new Refusal(Reason.WRONG_DESTINATION, "the destination is not this service provider: " + Text.safe(destination));
        }
    }

    private void requireIssuer(final Element issuer) {
        if (issuer == null) {
            return;
        }
        final String value = SafeXml.plainText(issuer);
        if (value == null || !config.idpEntityId().equals(value.trim())) {
            throw new Refusal(Reason.WRONG_ISSUER, "the issuer is not the identity provider: " + Text.safe(value));
        }
    }

    private static void requireSuccess(final Element response) {
        final Element status = SafeXml.requiredChild(response, Names.NS_SAMLP, "Status");
        final Element code = SafeXml.requiredChild(status, Names.NS_SAMLP, "StatusCode");
        if (!Names.STATUS_SUCCESS.equals(SafeXml.attr(code, "Value"))) {
            throw new Refusal(Reason.STATUS_NOT_SUCCESS, "the status is not success: " + Text.safe(SafeXml.attr(code, "Value")));
        }
    }
}
