# saml4j

SAML 2.0 Service Provider library for Java. SP-initiated Web Browser SSO (HTTP-Redirect AuthnRequest, HTTP-POST
Response, encrypted assertions) and Single Logout (HTTP-Redirect and HTTP-POST). One direct dependency: Apache Santuario (xmlsec).

## Maven

```xml
<dependency>
  <groupId>org.codelibs</groupId>
  <artifactId>saml4j</artifactId>
  <version>0.1.0</version>
</dependency>
```

## Usage

```java
ServiceProvider sp = ServiceProvider.create(SamlConfig.fromMap(properties));

// login
LoginStart start = sp.startLogin();                 // redirect to start.redirectUrl(); keep start.requestId()
LoginResult result = sp.finishLogin(samlResponse, pendingRequestIds);
if (result instanceof LoginResult.Authenticated a) {
    String user = a.nameId().value();
    Map<String, List<String>> attributes = a.attributes();
} else if (result instanceof LoginResult.Rejected r) {
    log(r.reason(), r.detail());                    // detail is sanitized for a log line
}

// logout
LogoutStart out = sp.startLogout(nameId, sessionIndex);
LogoutOutcome in = sp.handleLogout("GET", request.getQueryString(), sessionNameId, sessionIndex);
// or, for a message the IdP posted:
LogoutOutcome posted = sp.handleLogoutPost(samlRequest, samlResponse, relayState, sessionNameId, sessionIndex);

String metadata = sp.metadata();
```

## Configuration

`SamlConfig.fromMap` reads flat keys (a blank value counts as absent; anything unknown is refused):

| Key | |
|---|---|
| `idp.entityid`, `idp.single_sign_on_service.url`, `idp.x509cert` | required; `idp.x509certMulti.N` adds certificates |
| `idp.single_logout_service.url`, `sp.single_logout_service.url` | single logout (both or neither) |
| `sp.entityid`, `sp.assertion_consumer_service.url` | required |
| `sp.nameidformat` | NameID format to request |
| `sp.x509cert`, `sp.privatekey` | SP key pair (PKCS#8); needed for signing and for encrypted assertions |
| `security.authnrequest_signed` | sign the AuthnRequest |
| `security.want_messages_signed`, `security.want_assertions_signed` | require the Response / the Assertion to be signed (one of them always is) |
| `security.want_assertions_encrypted` | require an encrypted assertion |
| `security.want_logout_signed` | require signed logout messages (default `true`) |
| `security.allow_deprecated_alg` | accept SHA-1 signatures (default `false`) |
| `security.allow_rsa_1_5` | accept RSA 1.5 key transport (default `false`; OAEP only otherwise) |
| `security.clock_drift`, `security.max_message_size` | seconds (120) and bytes (1048576) |
| `security.requested_authncontext`, `security.requested_authncontextcomparison` | request an AuthnContext |
| `security.signature_algorithm` | the full URI of `rsa-sha256` (default), `rsa-sha384` or `rsa-sha512` |
| `strict` | only `true` is accepted; `debug` is accepted and ignored |

The Response must be signed, or its Assertion must be; the audience, recipient, issuer and validity period are always
checked, and so is the destination of a signed Response; a response must answer a request you started. IdP and SP
certificates must be RSA keys of at least 2048 bits. When the Response itself is not signed, an encrypted assertion that
fails for any reason is reported as one `DECRYPTION_FAILED`, so that the outcome tells a sender nothing about the plaintext.

## License

Apache License 2.0
