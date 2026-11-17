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

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import org.codelibs.saml4j.internal.Names;

/**
 * The configuration of a service provider. It is immutable and validated when it is built: a value that cannot be
 * parsed, a key that is not known and a combination that cannot work are all refused with a
 * {@link SamlConfigException} that names the key.
 *
 * <p>{@link #fromMap(Map)} reads the keys below (a blank value counts as absent):</p>
 * <ul>
 * <li>{@code idp.entityid}, {@code idp.single_sign_on_service.url}, {@code idp.x509cert} (required, or
 * {@code idp.x509certMulti.N} alone;
 * {@code idp.x509certMulti.1}, {@code .2}, ... add certificates for a key rollover)</li>
 * <li>{@code idp.single_logout_service.url}, {@code sp.single_logout_service.url}: single logout, both or neither</li>
 * <li>{@code sp.entityid}, {@code sp.assertion_consumer_service.url} (required), {@code sp.nameidformat}</li>
 * <li>{@code sp.x509cert}, {@code sp.privatekey} (PKCS#8): the SP key pair</li>
 * <li>{@code security.authnrequest_signed}, {@code security.want_messages_signed}, {@code security.want_assertions_signed},
 * {@code security.want_assertions_encrypted}, {@code security.want_logout_signed} (default true)</li>
 * <li>{@code security.allow_deprecated_alg}, {@code security.allow_rsa_1_5} (default false)</li>
 * <li>{@code security.clock_drift} (seconds, default 120), {@code security.max_message_size} (bytes, default 1048576)</li>
 * <li>{@code security.requested_authncontext}, {@code security.requested_authncontextcomparison},
 * {@code security.signature_algorithm}</li>
 * <li>{@code strict} (only {@code true} is accepted), {@code debug} (ignored)</li>
 * </ul>
 */
public final class SamlConfig {

    private static final Set<String> KEYS =
            Set.of("idp.entityid", "idp.single_sign_on_service.url", "idp.single_logout_service.url", "idp.x509cert", "sp.entityid",
                    "sp.assertion_consumer_service.url", "sp.single_logout_service.url", "sp.nameidformat", "sp.x509cert", "sp.privatekey",
                    "security.authnrequest_signed", "security.want_messages_signed", "security.want_assertions_signed",
                    "security.want_assertions_encrypted", "security.want_logout_signed", "security.allow_deprecated_alg",
                    "security.allow_rsa_1_5", "security.clock_drift", "security.max_message_size", "security.requested_authncontext",
                    "security.requested_authncontextcomparison", "security.signature_algorithm", "strict", "debug");

    private static final String MULTI_PREFIX = "idp.x509certMulti.";

    private static final Set<String> COMPARISONS = Set.of("exact", "minimum", "maximum", "better");

    private final String idpEntityId;

    private final String idpSsoUrl;

    private final String idpSloUrl;

    private final List<X509Certificate> idpCerts;

    private final String spEntityId;

    private final String acsUrl;

    private final String slsUrl;

    private final String nameIdFormat;

    private final X509Certificate spCert;

    private final PrivateKey spKey;

    private final boolean authnRequestSigned;

    private final boolean wantMessagesSigned;

    private final boolean wantAssertionsSigned;

    private final boolean wantAssertionsEncrypted;

    private final boolean wantLogoutSigned;

    private final boolean allowDeprecatedAlg;

    private final boolean allowRsa15;

    private final int clockDriftSeconds;

    private final int maxMessageSize;

    private final String requestedAuthnContext;

    private final String requestedAuthnContextComparison;

    private final String signatureAlgorithm;

    private final Clock clock;

    private final boolean metadataOnly;

    private SamlConfig(final Builder b) {
        metadataOnly = b.metadataOnly;
        idpEntityId = metadataOnly ? b.idpEntityId : require(b.idpEntityId, "idp.entityid");
        idpSsoUrl = metadataOnly ? b.idpSsoUrl : requireUrl(b.idpSsoUrl, "idp.single_sign_on_service.url");
        idpSloUrl = b.idpSloUrl == null ? null : requireUrl(b.idpSloUrl, "idp.single_logout_service.url");
        idpCerts = Collections.unmodifiableList(new ArrayList<>(b.idpCerts));
        idpCerts.forEach(c -> requireStrongKey(c, "idp.x509cert"));
        if (idpCerts.isEmpty() && !metadataOnly) {
            throw new SamlConfigException("idp.x509cert is required");
        }
        spEntityId = require(b.spEntityId, "sp.entityid");
        acsUrl = requireUrl(b.acsUrl, "sp.assertion_consumer_service.url");
        slsUrl = b.slsUrl == null ? null : requireUrl(b.slsUrl, "sp.single_logout_service.url");
        if (!metadataOnly && (idpSloUrl == null) != (slsUrl == null)) {
            throw new SamlConfigException("idp.single_logout_service.url and sp.single_logout_service.url must be set together");
        }
        nameIdFormat = b.nameIdFormat == null ? Names.NAMEID_UNSPECIFIED : b.nameIdFormat;
        spCert = b.spCert;
        if (spCert != null) {
            requireStrongKey(spCert, "sp.x509cert");
        }
        spKey = b.spKey;
        if (spKey != null && spCert != null && !matches(spCert, spKey)) {
            throw new SamlConfigException("sp.privatekey does not match sp.x509cert");
        }
        authnRequestSigned = b.authnRequestSigned;
        if (authnRequestSigned && spKey == null) {
            throw new SamlConfigException("security.authnrequest_signed requires sp.privatekey");
        }
        wantMessagesSigned = b.wantMessagesSigned;
        wantAssertionsSigned = b.wantAssertionsSigned;
        wantAssertionsEncrypted = b.wantAssertionsEncrypted;
        wantLogoutSigned = b.wantLogoutSigned;
        allowDeprecatedAlg = b.allowDeprecatedAlg;
        allowRsa15 = b.allowRsa15;
        if ((wantAssertionsEncrypted || allowRsa15) && spKey == null) {
            throw new SamlConfigException("encrypted assertions require sp.privatekey");
        }
        if (b.clockDriftSeconds < 0 || b.clockDriftSeconds > 600) {
            throw new SamlConfigException("security.clock_drift must be between 0 and 600");
        }
        clockDriftSeconds = b.clockDriftSeconds;
        if (b.maxMessageSize < 1024 || b.maxMessageSize > 16 * 1024 * 1024) {
            throw new SamlConfigException("security.max_message_size must be between 1024 and 16777216");
        }
        maxMessageSize = b.maxMessageSize;
        requestedAuthnContext = b.requestedAuthnContext;
        if (b.requestedAuthnContextComparison == null || !COMPARISONS.contains(b.requestedAuthnContextComparison)) {
            throw new SamlConfigException("security.requested_authncontextcomparison must be one of " + new TreeSet<>(COMPARISONS));
        }
        requestedAuthnContextComparison = b.requestedAuthnContextComparison;
        if (b.signatureAlgorithm == null || !Set.of(Names.RSA_SHA256, Names.RSA_SHA384, Names.RSA_SHA512).contains(b.signatureAlgorithm)) {
            throw new SamlConfigException("security.signature_algorithm must be rsa-sha256, rsa-sha384 or rsa-sha512");
        }
        signatureAlgorithm = b.signatureAlgorithm;
        if (b.clock == null) {
            throw new SamlConfigException("clock is required");
        }
        clock = b.clock;
    }

    /** Names a rejected key only when it looks like a setting name: a mistyped key is useful, a line of a pasted secret is not. */
    private static String describeKeys(final List<String> keys) {
        final List<String> shown = new ArrayList<>();
        for (final String k : keys) {
            if (shown.size() < 10 && k.matches("(strict|debug)|[A-Za-z][A-Za-z0-9_]{0,23}(\\.[A-Za-z0-9_]{0,32}){1,3}")) {
                shown.add(k);
            }
        }
        final int others = keys.size() - shown.size();
        return shown + (others > 0 ? " and " + others + " more" : "");
    }

    private static void requireStrongKey(final X509Certificate cert, final String key) {
        if (cert.getPublicKey() instanceof final java.security.interfaces.RSAPublicKey pub && pub.getModulus().bitLength() < 2048) {
            throw new SamlConfigException(key + " must be an RSA key of at least 2048 bits");
        }
    }

    /**
     * Creates a builder.
     *
     * @return a builder with the defaults
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builds a configuration from flat string properties. The keys are the ones listed in the class description,
     * without any prefix.
     *
     * @param props the properties
     * @return the configuration
     * @throws SamlConfigException if a value is malformed, a key is unknown or the combination is not valid
     */
    public static SamlConfig fromMap(final Map<String, String> props) {
        return parse(props, false);
    }

    /**
     * Builds a configuration that is good for nothing but the metadata of the service provider: the identity
     * provider keys are not needed, and are ignored when present. The result is refused by
     * {@link ServiceProvider#create(SamlConfig)}.
     *
     * @param props the properties, as for {@link #fromMap(Map)}
     * @return the configuration
     * @throws SamlConfigException if a service provider value is malformed or a key is unknown
     */
    public static SamlConfig fromMapForMetadata(final Map<String, String> props) {
        return parse(props, true);
    }

    private static SamlConfig parse(final Map<String, String> props, final boolean metadataOnly) {
        if (props == null) {
            throw new SamlConfigException("properties are required");
        }
        final Map<String, String> values = new TreeMap<>();
        final List<String> unknown = new ArrayList<>();
        for (final Map.Entry<String, String> e : props.entrySet()) {
            final String key = e.getKey();
            if (key == null) {
                unknown.add("null");
            } else if (key.startsWith(MULTI_PREFIX) && key.length() > MULTI_PREFIX.length() || KEYS.contains(key)) {
                if (e.getValue() != null && !e.getValue().isBlank()) {
                    values.put(key, e.getValue().trim());
                }
            } else {
                unknown.add(key);
            }
        }
        if (!unknown.isEmpty()) {
            Collections.sort(unknown);
            throw new SamlConfigException("unknown or unsupported keys: " + describeKeys(unknown));
        }
        if (values.containsKey("strict") && !"true".equalsIgnoreCase(values.get("strict"))) {
            throw new SamlConfigException("strict must be true");
        }
        final Builder b = builder();
        b.metadataOnly = metadataOnly;
        if (!metadataOnly) {
            b.idpEntityId(values.get("idp.entityid"));
            b.idpSingleSignOnServiceUrl(values.get("idp.single_sign_on_service.url"));
            b.idpSingleLogoutServiceUrl(values.get("idp.single_logout_service.url"));
            if (values.containsKey("idp.x509cert")) {
                b.addIdpCertificate(parseCertificate(values.get("idp.x509cert"), "idp.x509cert"));
            }
            for (final Map.Entry<String, String> e : values.entrySet()) {
                if (e.getKey().startsWith(MULTI_PREFIX)) {
                    b.addIdpCertificate(parseCertificate(e.getValue(), e.getKey()));
                }
            }
        }
        b.spEntityId(values.get("sp.entityid"));
        b.assertionConsumerServiceUrl(values.get("sp.assertion_consumer_service.url"));
        b.singleLogoutServiceUrl(values.get("sp.single_logout_service.url"));
        b.nameIdFormat(values.get("sp.nameidformat"));
        if (values.containsKey("sp.x509cert")) {
            b.spCertificate(parseCertificate(values.get("sp.x509cert"), "sp.x509cert"));
        }
        if (values.containsKey("sp.privatekey")) {
            b.spPrivateKey(parsePrivateKey(values.get("sp.privatekey")));
        }
        b.authnRequestSigned(bool(values, "security.authnrequest_signed", false));
        b.wantMessagesSigned(bool(values, "security.want_messages_signed", false));
        b.wantAssertionsSigned(bool(values, "security.want_assertions_signed", false));
        b.wantAssertionsEncrypted(bool(values, "security.want_assertions_encrypted", false));
        b.wantLogoutSigned(bool(values, "security.want_logout_signed", true));
        b.allowDeprecatedAlg(bool(values, "security.allow_deprecated_alg", false));
        b.allowRsa15(bool(values, "security.allow_rsa_1_5", false));
        b.clockDriftSeconds(integer(values, "security.clock_drift", 120));
        b.maxMessageSize(integer(values, "security.max_message_size", 1024 * 1024));
        b.requestedAuthnContext(values.get("security.requested_authncontext"));
        if (values.containsKey("security.requested_authncontextcomparison")) {
            b.requestedAuthnContextComparison(values.get("security.requested_authncontextcomparison"));
        }
        if (values.containsKey("security.signature_algorithm")) {
            b.signatureAlgorithm(values.get("security.signature_algorithm"));
        }
        return b.build();
    }

    private static boolean bool(final Map<String, String> values, final String key, final boolean def) {
        final String v = values.get(key);
        if (v == null) {
            return def;
        }
        if ("true".equalsIgnoreCase(v)) {
            return true;
        }
        if ("false".equalsIgnoreCase(v)) {
            return false;
        }
        throw new SamlConfigException(key + " must be true or false");
    }

    private static int integer(final Map<String, String> values, final String key, final int def) {
        final String v = values.get(key);
        if (v == null) {
            return def;
        }
        try {
            if (!v.matches("[0-9]{1,9}")) {
                throw new NumberFormatException();
            }
            return Integer.parseInt(v);
        } catch (final NumberFormatException e) {
            throw new SamlConfigException(key + " must be an integer");
        }
    }

    private static String require(final String value, final String key) {
        if (value == null || value.isBlank()) {
            throw new SamlConfigException(key + " is required");
        }
        return value;
    }

    private static String requireUrl(final String value, final String key) {
        require(value, key);
        try {
            final URI uri = new URI(value);
            if (!"https".equalsIgnoreCase(uri.getScheme()) && !"http".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null) {
                throw new SamlConfigException(key + " must be an http or https URL");
            }
            if (uri.getRawFragment() != null) {
                throw new SamlConfigException(key + " must not have a fragment");
            }
        } catch (final java.net.URISyntaxException e) {
            throw new SamlConfigException(key + " is not a valid URL");
        }
        return value;
    }

    private static boolean matches(final X509Certificate cert, final PrivateKey key) {
        if (cert.getPublicKey() instanceof final java.security.interfaces.RSAPublicKey pub
                && key instanceof final java.security.interfaces.RSAPrivateKey priv) {
            if (!pub.getModulus().equals(priv.getModulus())) {
                return false;
            }
            return !(key instanceof final java.security.interfaces.RSAPrivateCrtKey crt)
                    || pub.getPublicExponent().equals(crt.getPublicExponent());
        }
        return false;
    }

    static X509Certificate parseCertificate(final String text, final String key) {
        try {
            final String body = text.replaceAll("-----(BEGIN|END) CERTIFICATE-----", "").replaceAll("\\s", "");
            final byte[] der = Base64.getDecoder().decode(body);
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
        } catch (final Exception e) {
            throw new SamlConfigException(key + " is not a certificate");
        }
    }

    static PrivateKey parsePrivateKey(final String text) {
        if (text.contains("BEGIN RSA PRIVATE KEY") || text.contains("BEGIN EC PRIVATE KEY")) {
            throw new SamlConfigException("sp.privatekey must be PKCS#8 (BEGIN PRIVATE KEY)");
        }
        try {
            final String body = text.replaceAll("-----(BEGIN|END) PRIVATE KEY-----", "").replaceAll("\\s", "");
            final byte[] der = Base64.getDecoder().decode(body);
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } catch (final Exception e) {
            throw new SamlConfigException("sp.privatekey is not an RSA PKCS#8 key");
        }
    }

    /**
     * Returns the entity ID of the identity provider.
     *
     * @return the entity ID of the identity provider
     */
    public String idpEntityId() {
        return idpEntityId;
    }

    /**
     * Returns the single sign-on URL of the identity provider.
     *
     * @return the single sign-on URL of the identity provider
     */
    public String idpSingleSignOnServiceUrl() {
        return idpSsoUrl;
    }

    /**
     * Returns the single logout URL of the identity provider, or {@code null}.
     *
     * @return the single logout URL of the identity provider, or {@code null}
     */
    public String idpSingleLogoutServiceUrl() {
        return idpSloUrl;
    }

    /**
     * Returns the certificates that may sign for the identity provider.
     *
     * @return the certificates that may sign for the identity provider
     */
    public List<X509Certificate> idpCertificates() {
        return idpCerts;
    }

    /**
     * Returns the entity ID of this service provider.
     *
     * @return the entity ID of this service provider
     */
    public String spEntityId() {
        return spEntityId;
    }

    /**
     * Returns the assertion consumer service URL.
     *
     * @return the assertion consumer service URL
     */
    public String assertionConsumerServiceUrl() {
        return acsUrl;
    }

    /**
     * Returns the single logout service URL, or {@code null}.
     *
     * @return the single logout service URL, or {@code null}
     */
    public String singleLogoutServiceUrl() {
        return slsUrl;
    }

    /**
     * Returns the NameID format requested.
     *
     * @return the NameID format requested
     */
    public String nameIdFormat() {
        return nameIdFormat;
    }

    /**
     * Returns the certificate of this service provider, or {@code null}.
     *
     * @return the certificate of this service provider, or {@code null}
     */
    public X509Certificate spCertificate() {
        return spCert;
    }

    /**
     * Returns the private key of this service provider, or {@code null}.
     *
     * @return the private key of this service provider, or {@code null}
     */
    public PrivateKey spPrivateKey() {
        return spKey;
    }

    /**
     * Returns whether AuthnRequests are signed.
     *
     * @return whether AuthnRequests are signed
     */
    public boolean authnRequestSigned() {
        return authnRequestSigned;
    }

    /**
     * Returns whether the Response itself must be signed.
     *
     * @return whether the Response itself must be signed
     */
    public boolean wantMessagesSigned() {
        return wantMessagesSigned;
    }

    /**
     * Returns whether the Assertion itself must be signed.
     *
     * @return whether the Assertion itself must be signed
     */
    public boolean wantAssertionsSigned() {
        return wantAssertionsSigned;
    }

    /**
     * Returns whether the Assertion must be encrypted.
     *
     * @return whether the Assertion must be encrypted
     */
    public boolean wantAssertionsEncrypted() {
        return wantAssertionsEncrypted;
    }

    /**
     * Returns whether logout messages must be signed.
     *
     * @return whether logout messages must be signed
     */
    public boolean wantLogoutSigned() {
        return wantLogoutSigned;
    }

    /**
     * Returns whether SHA-1 based algorithms are accepted.
     *
     * @return whether SHA-1 based algorithms are accepted
     */
    public boolean allowDeprecatedAlg() {
        return allowDeprecatedAlg;
    }

    /**
     * Returns whether RSA 1.5 key transport is accepted.
     *
     * @return whether RSA 1.5 key transport is accepted
     */
    public boolean allowRsa15() {
        return allowRsa15;
    }

    /**
     * Returns the clock drift tolerated, in seconds.
     *
     * @return the clock drift tolerated, in seconds
     */
    public int clockDriftSeconds() {
        return clockDriftSeconds;
    }

    /**
     * Returns the largest decoded message accepted, in bytes.
     *
     * @return the largest decoded message accepted, in bytes
     */
    public int maxMessageSize() {
        return maxMessageSize;
    }

    /**
     * Returns the requested AuthnContextClassRef, or {@code null}.
     *
     * @return the requested AuthnContextClassRef, or {@code null}
     */
    public String requestedAuthnContext() {
        return requestedAuthnContext;
    }

    /**
     * Returns the comparison for the requested AuthnContext.
     *
     * @return the comparison for the requested AuthnContext
     */
    public String requestedAuthnContextComparison() {
        return requestedAuthnContextComparison;
    }

    /**
     * Returns the signature algorithm URI used for outgoing signatures.
     *
     * @return the signature algorithm URI used for outgoing signatures
     */
    public String signatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * Returns the clock.
     *
     * @return the clock
     */
    public Clock clock() {
        return clock;
    }

    /**
     * Returns whether this configuration can only be used to produce metadata.
     *
     * @return whether this configuration can only be used to produce metadata
     */
    public boolean metadataOnly() {
        return metadataOnly;
    }

    /** Builds a {@link SamlConfig}. */
    public static final class Builder {

        private String idpEntityId;

        private String idpSsoUrl;

        private String idpSloUrl;

        private final List<X509Certificate> idpCerts = new ArrayList<>();

        private String spEntityId;

        private String acsUrl;

        private String slsUrl;

        private String nameIdFormat;

        private X509Certificate spCert;

        private PrivateKey spKey;

        private boolean authnRequestSigned;

        private boolean wantMessagesSigned;

        private boolean wantAssertionsSigned;

        private boolean wantAssertionsEncrypted;

        private boolean wantLogoutSigned = true;

        private boolean allowDeprecatedAlg;

        private boolean allowRsa15;

        private int clockDriftSeconds = 120;

        private int maxMessageSize = 1024 * 1024;

        private String requestedAuthnContext;

        private String requestedAuthnContextComparison = "exact";

        private String signatureAlgorithm = Names.RSA_SHA256;

        private Clock clock = Clock.systemUTC();

        private boolean metadataOnly;

        private Builder() {
        }

        /**
         * Sets the IdP entity ID.
         *
         * @param v the IdP entity ID
         * @return this builder
         */
        public Builder idpEntityId(final String v) {
            idpEntityId = v;
            return this;
        }

        /**
         * Sets the IdP single sign-on URL.
         *
         * @param v the IdP single sign-on URL
         * @return this builder
         */
        public Builder idpSingleSignOnServiceUrl(final String v) {
            idpSsoUrl = v;
            return this;
        }

        /**
         * Sets the IdP single logout URL, or {@code null}.
         *
         * @param v the IdP single logout URL, or {@code null}
         * @return this builder
         */
        public Builder idpSingleLogoutServiceUrl(final String v) {
            idpSloUrl = v;
            return this;
        }

        /**
         * Sets a certificate that may sign for the IdP.
         *
         * @param c a certificate that may sign for the IdP
         * @return this builder
         */
        public Builder addIdpCertificate(final X509Certificate c) {
            if (c == null) {
                throw new SamlConfigException("an identity provider certificate is required");
            }
            idpCerts.add(c);
            return this;
        }

        /**
         * Sets the SP entity ID.
         *
         * @param v the SP entity ID
         * @return this builder
         */
        public Builder spEntityId(final String v) {
            spEntityId = v;
            return this;
        }

        /**
         * Sets the assertion consumer service URL.
         *
         * @param v the assertion consumer service URL
         * @return this builder
         */
        public Builder assertionConsumerServiceUrl(final String v) {
            acsUrl = v;
            return this;
        }

        /**
         * Sets the single logout service URL, or {@code null}.
         *
         * @param v the single logout service URL, or {@code null}
         * @return this builder
         */
        public Builder singleLogoutServiceUrl(final String v) {
            slsUrl = v;
            return this;
        }

        /**
         * Sets the NameID format, or {@code null} for unspecified.
         *
         * @param v the NameID format, or {@code null} for unspecified
         * @return this builder
         */
        public Builder nameIdFormat(final String v) {
            nameIdFormat = v;
            return this;
        }

        /**
         * Sets the SP certificate.
         *
         * @param c the SP certificate
         * @return this builder
         */
        public Builder spCertificate(final X509Certificate c) {
            spCert = c;
            return this;
        }

        /**
         * Sets the SP private key.
         *
         * @param k the SP private key
         * @return this builder
         */
        public Builder spPrivateKey(final PrivateKey k) {
            spKey = k;
            return this;
        }

        /**
         * Sets whether to sign AuthnRequests.
         *
         * @param v whether to sign AuthnRequests
         * @return this builder
         */
        public Builder authnRequestSigned(final boolean v) {
            authnRequestSigned = v;
            return this;
        }

        /**
         * Sets whether the Response must be signed.
         *
         * @param v whether the Response must be signed
         * @return this builder
         */
        public Builder wantMessagesSigned(final boolean v) {
            wantMessagesSigned = v;
            return this;
        }

        /**
         * Sets whether the Assertion must be signed.
         *
         * @param v whether the Assertion must be signed
         * @return this builder
         */
        public Builder wantAssertionsSigned(final boolean v) {
            wantAssertionsSigned = v;
            return this;
        }

        /**
         * Sets whether the Assertion must be encrypted.
         *
         * @param v whether the Assertion must be encrypted
         * @return this builder
         */
        public Builder wantAssertionsEncrypted(final boolean v) {
            wantAssertionsEncrypted = v;
            return this;
        }

        /**
         * Sets whether logout messages must be signed.
         *
         * @param v whether logout messages must be signed
         * @return this builder
         */
        public Builder wantLogoutSigned(final boolean v) {
            wantLogoutSigned = v;
            return this;
        }

        /**
         * Sets whether SHA-1 based algorithms are accepted.
         *
         * @param v whether SHA-1 based algorithms are accepted
         * @return this builder
         */
        public Builder allowDeprecatedAlg(final boolean v) {
            allowDeprecatedAlg = v;
            return this;
        }

        /**
         * Sets whether RSA 1.5 key transport is accepted.
         *
         * @param v whether RSA 1.5 key transport is accepted
         * @return this builder
         */
        public Builder allowRsa15(final boolean v) {
            allowRsa15 = v;
            return this;
        }

        /**
         * Sets the clock drift in seconds.
         *
         * @param v the clock drift in seconds
         * @return this builder
         */
        public Builder clockDriftSeconds(final int v) {
            clockDriftSeconds = v;
            return this;
        }

        /**
         * Sets the largest decoded message in bytes.
         *
         * @param v the largest decoded message in bytes
         * @return this builder
         */
        public Builder maxMessageSize(final int v) {
            maxMessageSize = v;
            return this;
        }

        /**
         * Sets the AuthnContextClassRef to request, or {@code null}.
         *
         * @param v the AuthnContextClassRef to request, or {@code null}
         * @return this builder
         */
        public Builder requestedAuthnContext(final String v) {
            requestedAuthnContext = v;
            return this;
        }

        /**
         * Sets the comparison method for the requested AuthnContext: exact, minimum, maximum or better.
         *
         * @param v exact, minimum, maximum or better
         * @return this builder
         */
        public Builder requestedAuthnContextComparison(final String v) {
            requestedAuthnContextComparison = v;
            return this;
        }

        /**
         * Sets the outgoing signature algorithm URI.
         *
         * @param v the outgoing signature algorithm URI
         * @return this builder
         */
        public Builder signatureAlgorithm(final String v) {
            signatureAlgorithm = v;
            return this;
        }

        /**
         * Sets the clock, for tests.
         *
         * @param v the clock, for tests
         * @return this builder
         */
        public Builder clock(final Clock v) {
            clock = v;
            return this;
        }

        /**
         * Validates and builds the configuration.
         *
         * @return the configuration
         * @throws SamlConfigException if it is not valid
         */
        public SamlConfig build() {
            return new SamlConfig(this);
        }
    }
}
