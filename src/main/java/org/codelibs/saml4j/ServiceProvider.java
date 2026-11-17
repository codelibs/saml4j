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
import java.util.Set;

import org.codelibs.saml4j.internal.LogoutHandler;
import org.codelibs.saml4j.internal.Messages;
import org.codelibs.saml4j.internal.RedirectBinding;
import org.codelibs.saml4j.internal.ResponseValidator;

/**
 * A SAML 2.0 service provider. An instance is immutable and thread-safe: build one from a {@link SamlConfig} and
 * keep it for as long as the configuration is the same.
 *
 * <pre>
 * ServiceProvider sp = ServiceProvider.create(SamlConfig.fromMap(props));
 *
 * LoginStart start = sp.startLogin();                       // redirect the browser, remember start.requestId()
 * LoginResult result = sp.finishLogin(samlResponse, pendingRequestIds);
 * if (result instanceof LoginResult.Authenticated a) {
 *     // a.nameId(), a.attributes(), ...
 * }
 *
 * LogoutOutcome outcome = sp.handleLogout("GET", request.getQueryString(), sessionNameId, sessionIndex);
 * </pre>
 *
 * <p>Nothing here throws for a message that someone sent: it is refused with a {@link Reason} and a sanitized
 * detail, and this library writes nothing to a log. The detail may be logged as it is. The XML security library
 * writes a warning when a signature fails; what it quotes is a validated name or a computed value.</p>
 */
public final class ServiceProvider {

    private final SamlConfig config;

    private final Messages messages;

    private final ResponseValidator responses;

    private final LogoutHandler logouts;

    private ServiceProvider(final SamlConfig config, final ReplayCache replayCache) {
        this.config = config;
        this.messages = new Messages(config);
        this.responses = new ResponseValidator(config, replayCache);
        this.logouts = new LogoutHandler(config, replayCache, messages);
    }

    /**
     * Creates a service provider with an in-memory replay cache.
     *
     * @param config the configuration
     * @return the service provider
     */
    public static ServiceProvider create(final SamlConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("config is required");
        }
        return create(config, new InMemoryReplayCache(InMemoryReplayCache.DEFAULT_MAX_ENTRIES, config.clock()));
    }

    /**
     * Creates a service provider.
     *
     * @param config the configuration
     * @param replayCache the replay cache; share one between instances that serve the same SP
     * @return the service provider
     */
    public static ServiceProvider create(final SamlConfig config, final ReplayCache replayCache) {
        if (config == null || replayCache == null) {
            throw new IllegalArgumentException("config and replayCache are required");
        }
        if (config.metadataOnly()) {
            throw new IllegalArgumentException("a metadata-only configuration cannot be used to create a service provider");
        }
        return new ServiceProvider(config, replayCache);
    }

    /**
     * Returns the metadata of a service provider that has no identity provider configured yet, which is what an
     * identity provider is registered from.
     *
     * @param config the configuration, from {@link SamlConfig#fromMapForMetadata(java.util.Map)} or a builder
     * @return the metadata XML
     */
    public static String metadataOf(final SamlConfig config) {
        if (config == null) {
            throw new IllegalArgumentException("config is required");
        }
        return new Messages(config).metadata();
    }

    /**
     * Returns the configuration.
     *
     * @return the configuration
     */
    public SamlConfig config() {
        return config;
    }

    /**
     * Returns the metadata of this service provider.
     *
     * @return the metadata XML
     */
    public String metadata() {
        return messages.metadata();
    }

    /**
     * Starts a login.
     *
     * @return the URL to redirect the browser to, and the ID of the request
     */
    public LoginStart startLogin() {
        final String id = Messages.newId();
        final String xml = messages.authnRequest(id, config.clock().instant());
        final String url = RedirectBinding.build(config.idpSingleSignOnServiceUrl(), "SAMLRequest", xml, null,
                config.authnRequestSigned() ? config.spPrivateKey() : null, config.signatureAlgorithm());
        return new LoginStart(url, id);
    }

    /**
     * Finishes a login.
     *
     * @param samlResponse the {@code SAMLResponse} parameter of the POST to the assertion consumer service
     * @param pendingRequestIds the IDs of the requests started and not answered yet; the response must answer one
     * @return the result
     */
    public LoginResult finishLogin(final String samlResponse, final Set<String> pendingRequestIds) {
        return responses.validate(samlResponse, pendingRequestIds);
    }

    /**
     * Starts a logout at the identity provider.
     *
     * @param nameId the subject of the login
     * @param sessionIndex the session index of the login, or {@code null}
     * @return the URL to redirect the browser to, and the ID of the request
     * @throws IllegalStateException if single logout is not configured
     */
    public LogoutStart startLogout(final NameId nameId, final String sessionIndex) {
        if (config.singleLogoutServiceUrl() == null) {
            throw new IllegalStateException("single logout is not configured");
        }
        if (nameId == null) {
            throw new IllegalArgumentException("nameId is required");
        }
        final Instant now = config.clock().instant();
        final String id = Messages.newId();
        final String url = RedirectBinding.build(config.idpSingleLogoutServiceUrl(), "SAMLRequest",
                messages.logoutRequest(id, now, nameId, sessionIndex), null, config.spPrivateKey(), config.signatureAlgorithm());
        return new LogoutStart(url, id);
    }

    /**
     * Handles a message that arrived at the single logout service by HTTP-POST. The message carries an XML
     * signature instead of the query signature of the redirect binding; every other rule is the same.
     *
     * @param samlRequest the {@code SAMLRequest} form parameter, or {@code null}
     * @param samlResponse the {@code SAMLResponse} form parameter, or {@code null}
     * @param relayState the {@code RelayState} form parameter, or {@code null}
     * @param sessionNameId the NameID of the SAML login of the current session, or {@code null} if there is none
     * @param sessionIndex the SessionIndex of that login, or {@code null}
     * @return what to do with the session and where to send the browser
     */
    public LogoutOutcome handleLogoutPost(final String samlRequest, final String samlResponse, final String relayState,
            final String sessionNameId, final String sessionIndex) {
        return logouts.handlePost(samlRequest, samlResponse, relayState, sessionNameId, sessionIndex);
    }

    /**
     * Handles a message that arrived at the single logout service by HTTP-Redirect.
     *
     * @param method the HTTP method of the request
     * @param rawQuery the query string exactly as received (not decoded)
     * @param sessionNameId the NameID of the SAML login of the current session, or {@code null} if there is none
     * @param sessionIndex the SessionIndex of that login, or {@code null}
     * @return what to do with the session and where to send the browser
     */
    public LogoutOutcome handleLogout(final String method, final String rawQuery, final String sessionNameId, final String sessionIndex) {
        return logouts.handle(method, rawQuery, sessionNameId, sessionIndex);
    }
}
