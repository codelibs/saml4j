# CLAUDE.md - AI Assistant Guide for CodeLibs saml4j

Java 17 SAML 2.0 service provider library. Maven build system, Apache License 2.0.

## Repository Structure

```
src/main/java/org/codelibs/saml4j/
├── ServiceProvider.java     # Entry point: startLogin / finishLogin / startLogout / handleLogout / metadata
├── SamlConfig.java          # Immutable, validated configuration (fromMap for flat properties)
├── LoginResult.java         # Sealed result: Authenticated | Rejected
├── LogoutOutcome.java       # END_SESSION | KEEP_SESSION | REJECTED
├── ReplayCache.java, InMemoryReplayCache.java
├── NameId.java, LoginStart.java, LogoutStart.java, Reason.java, SamlConfigException.java
└── internal/                # Not API
    ├── SafeXml.java         # Decoding, parsing and limits for untrusted input
    ├── XmlSecurity.java     # Signature verification and decryption (allow-lists in front of xmlsec)
    ├── ResponseValidator.java, LogoutHandler.java, RedirectBinding.java, Messages.java
    └── Names.java, Text.java, Times.java, Refusal.java
src/test/java/               # TestIdp is the fixture: it builds signed and encrypted messages
```

## Development Commands

```bash
mvn test                              # Run tests
mvn test -Dtest=ClassName#methodName  # Run specific test
mvn clean package                     # Build
mvn formatter:format                  # Format code
mvn license:format                    # Apply license headers
mvn verify                            # Generate coverage report
```

## Design Rules

- A message that someone sent is never an exception: it is a `LoginResult.Rejected` or a `LogoutOutcome` with a
  `Reason` and a sanitized `detail`. Only a bad configuration throws (`SamlConfigException`).
- Everything the result reports is read from the element that was verified. Do not re-query the raw document.
- Every algorithm URI and every element in a signature or an encrypted block is checked against an allow-list in
  `XmlSecurity` before the XML security library sees it. Add to the lists in `Names`, not around them.
- The library does not log; the XML security library warns when a signature fails, and what it quotes (a reference ID, a
  digest value) has been validated as a plain name or is a computed value. Text taken from a message reaches a caller
  only through `Text.safe`.
- Redirect-binding values are verified and decoded from the same raw query pairs; a repeated name is refused.
- Configuration is validated when it is built. An unknown key, an unparsable value or a combination that cannot work is a
  `SamlConfigException`; nothing falls back to a weaker default.
- Nothing recurses on the shape of the input. `SafeXml` limits depth and element count and traverses with an explicit stack.
- A new check needs a test that is red without it and a control test that is green with the same input minus the problem.

## Code Conventions

- Public API in `org.codelibs.saml4j`; `internal` is not API.
- Javadoc on every public type and member.
- Tests: JUnit 5, deterministic clock (`TestIdp.CLOCK`), test keys are throwaway ones under `src/test/resources/keys`.
