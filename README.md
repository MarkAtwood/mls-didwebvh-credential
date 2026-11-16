# draft-atwood-mls-didwebvh-credential

An Internet-Draft defining an MLS credential type in which the user, not
their messaging provider, authorizes the user's devices. The credential
carries a did:webvh log, and group members verify it without network
access.

Version -00 was posted on 16 November 2026 (dated 14 November) as an
individual submission:
<https://datatracker.ietf.org/doc/draft-atwood-mls-didwebvh-credential/>

## Why

In MLS as deployed with MIMI, each provider is the Authentication Service
for its own users. A provider can add a device to every room its users are
in. At best, key transparency lets the user detect it (RFC 9750
§8.4.3.1). This draft makes that attack fail validation instead.

For a readable overview, see [ietf127/](ietf127/), the notes that go
with the MLS session at IETF 127 (20 November 2026).

## Files

- `draft-atwood-mls-didwebvh-credential.md`: the draft, in kramdown-rfc
  source.
- `draft-atwood-mls-didwebvh-credential-00.xml`: the RFCXML built from it.
- `mls-mimi-credential-problem-statement.md`: a one-page statement of the
  problem and the requirements a fix must meet.
- `mimi-protocol-threat-model-proposed-text.md`: proposed threat model text
  for draft-ietf-mimi-protocol-07 Section 9.
- `ietf127/`: reading notes for the IETF 127 MLS session, with the
  diagram from the slides.

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
