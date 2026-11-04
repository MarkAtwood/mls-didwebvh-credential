# draft-atwood-mls-didwebvh-credential

An Internet-Draft defining an MLS credential type in which the user, not
their messaging provider, authorizes the user's devices. The credential
carries a did:webvh log, and group members verify it without network
access.

This draft has not yet been submitted to the IETF datatracker.

## Why

In MLS as deployed with MIMI, each provider is the Authentication Service
for its own users. A provider can add a device to every room its users are
in, and other members can detect this only after the fact (RFC 9750
§8.4.3.1). This draft makes that attack fail validation instead.

## Files

- `draft-atwood-mls-didwebvh-credential.md`: the draft, in kramdown-rfc
  source.
- `draft-atwood-mls-didwebvh-credential-00.xml`: the RFCXML built from it.
- `mls-mimi-credential-problem-statement.md`: a one-page statement of the
  problem and the requirements a fix must meet.
- `mimi-protocol-threat-model-proposed-text.md`: proposed threat model text
  for draft-ietf-mimi-protocol-07 Section 9.

## Building

```sh
kramdown-rfc draft-atwood-mls-didwebvh-credential.md > draft-atwood-mls-didwebvh-credential-00.xml
xml2rfc --text --html draft-atwood-mls-didwebvh-credential-00.xml
```

kramdown-rfc is the `kramdown-rfc` Ruby gem. xml2rfc is the `xml2rfc`
Python package.

## Discussion

Discussion belongs on the IETF MLS mailing list, mls@ietf.org. Issues
and pull requests here are welcome too.
